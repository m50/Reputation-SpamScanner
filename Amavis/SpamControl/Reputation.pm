###  /usr/local/lib/perl5/site_perl/Amavis/SpamControl
package Amavis::SpamControl::Reputation;
use warnings;
use Net::DNS;
use Net::DNS::Resolver;

BEGIN {
  import Amavis::Util qw(do_log);
}

sub new {
    my($class, $scanner_name, $module, @args) = @_;
    my(%options) = @args;
    my $self = bless { scanner_name => $scanner_name, options => \%options }, $class;
    $self->{version} = '1.0';
    $self->{prefix} = "ST";
    $self;
}

sub init_pre_chroot {

}

sub init_pre_fork {
    my $self = $_[0];
    my $dbname = "database";
    my ($username, $password) = qw(username password);
    # my $dbname = "mail";
    # my ($username, $password) = qw(mailu mail-passwd);

    $self->{filter_outbound} = 0;

    ## Establish Database Connection
    my $db = DBI->connect_cached("DBI:Pg:dbname=$dbname;host=127.0.0.1;port=5432", $username, $password);
    $self->{db} = $db;

    $self->{ip}->{dnsbls} = [ "rep.titanhq.com", "score.senderscore.org", "rep.mailspike.net" ];

    $self->{spf}->{get} = "SELECT spf_pass, spf_fail FROM reputation WHERE from_addr = ? AND env_from_domain = ?";
    $self->{spf}->{set} = "SELECT upsert_reputation_spf(?, ?, ?, ?)";

    $self->{dkim}->{get} = "SELECT dkim_pass, dkim_pass_au, dkim_fail, dkim_unknown FROM reputation WHERE from_addr = ? AND env_from_domain = ?";
    $self->{dkim}->{set} = "SELECT upsert_reputation_dkim(?, ?, ?, ?, ?, ?)";

    $self->{address}->{get} = "SELECT spam, ham FROM reputation WHERE from_addr = ? AND env_from_domain = ?";
    $self->{address}->{set} = "SELECT upsert_reputation_address(?, ?, ?, ?)";
}

sub check {
    my ($self,$msginfo) = @_;
    my $spam_report = $msginfo->spam_report;
    for my $r (@{$msginfo->per_recip_data}) {
        $self->{sa_score} = $r->spam_level;
        $self->{client_addr} = $msginfo->client_addr;
        $self->{mail_id} = $msginfo->mail_id;
        (my $sender_user, $self->{env_from}) = split /\@/, $msginfo->sender;
        $self->{from} = $msginfo->rfc2822_from;
        $self->{spf_result} = "unknown";
        $self->{dkim_result} = "unknown";
        my $score = 0;
        $self->dbg("sa_score: ".$self->{sa_score});

        if($spam_report =~ /BOUNCE_MESSAGE/) {
            $self->syslog("Skipping Bounce Mail");
            return 0;
        }

        if($spam_report =~ /ALL_TRUSTED/ && $self->{filter_outbound} == 0) {
            $self->syslog("Skipping Outbound Mail");
            return 0;
        }

        if($spam_report =~ /SPF(?:_HELO)?_PASS/) {
            $self->{spf_result} = "pass";
        } elsif ($spam_report =~ /SPF(?:_HELO)?_(?:SOFT)?FAIL/) {
            $self->{spf_result} = "fail";
        }

        if($spam_report =~ /DKIM_VALID_AU/) {
            $self->{dkim_result} = "pass au";
        } elsif($spam_report =~ /DKIM_VALID/) {
            $self->{dkim_result} = "pass";
        } elsif ($spam_report =~ /T_DKIM_INVALID/) {
            $self->{dkim_result} = "fail";
        }
        #### Score calculations
        # We need to normalize the reputation into a range of 10 (perfectly good score) and -10 (perfectly bad score).
        # Perfect reputations will get a score of 10 removed from the overall score, and those with the absolute worst reputation will
        #     get a score of 10 added to the overall score.
        # This then combines with the overall outcome from SpamAssassin, so that if a message scores -3 on SpamAssassin, but the sender has a -400 overall
        #     reputation, then the mail's overall score would equal 7, and still get marked as spam
        $score = $self->calc_rep;
        $msginfo->header_edits->add_header('X-Spam-Reputation', "$score;", 1);
        $score = $self->normalize(100, $score, -100, 5, -5) * -1 * $self->{options}->{'score_factor'};
        $self->dbg("score_factor: ".$self->{options}->{'score_factor'});
        $score = sprintf("%.3f", $score);
        $self->dbg("Final Score: $score");

        my $spam_test = $self->{prefix}.".".$self->{scanner_name}."=$score";
        $msginfo->supplementary_info('SCORE-'.$self->{scanner_name}, $score);
        $msginfo->supplementary_info('VERDICT-'.$self->{scanner_name}, $score >= 0 ? 'Ham' : $score < 0 ? 'Spam' : 'Unknown');
        $r->spam_level($self->{sa_score} + $score);
        unshift(@{$r->spam_tests}, \$spam_test);
    }

    1;
}

sub syslog { my ($self, $log) = @_; do_log(0, $self->{scanner_name}."; mail_id:".$self->{mail_id}."; $log"); }
sub dbg { my ($self, $log) = @_; do_log(1, $self->{scanner_name}."; mail_id:".$self->{mail_id}."; $log"); }

sub calc_rep {
    my ($self) = shift;

    my $spf_rep = $self->calc_spf_rep;
    my $dkim_rep = $self->calc_dkim_rep;
    my $address_rep = $self->calc_address_rep;
    my $ip_rep = $self->get_ip_rep;
    my $rep = 0;

    #### Weighted Reputation
    # The 4 reputations are on a -100 to 100 basis, so adding them all together will result a -400 to 400 range. We want this to be a -100 to 100 range.
    $rep = $self->normalize(300, ($dkim_rep / 2) + ($spf_rep / 2) + $address_rep + $ip_rep, -300);
    $rep = sprintf("%.3f", $rep);

    $self->syslog("From: <".$self->{from}.">; Envelope From Domain: <".$self->{env_from}.">; IP: <".$self->{client_addr}.">;");
    $self->syslog("SPF Reputation: $spf_rep; DKIM Reputation: $dkim_rep; Address Reputation: $address_rep; IP Reputation: $ip_rep; Weighted Reputation: $rep;");
    return $rep;
}

sub calc_spf_rep {
    my ($self) = @_;
    my $rep = 0;
    my ($spf_pass, $spf_fail) = qw(0 0);
    #### SPF Reputation
    # This reputation is based on how many "pass" vs. "fail" vs. "unkown" results there are.
    # Fail = -1
    # Pass = +1

    my $pdh = $self->{db}->prepare($self->{spf}->{get});
    $pdh->execute($self->{from}, $self->{env_from});
    while (my $row = $pdh->fetchrow_hashref) {
        $spf_pass += $row->{spf_pass};
        $spf_fail += $row->{spf_fail};
        $rep += $row->{spf_pass};
        $rep -= $row->{spf_fail};
    }
    $pdh->finish;

    # If there is no SPF Reputation, we have to make something up
    if($rep == 0) {
        if ($self->{spf_result} eq "fail") {
            $rep -= 10;
            $spf_fail += 1;
        } elsif ($self->{spf_result} eq "unknown") {
            $rep -= 5;
        } else {
            $spf_pass += 1;
        }
    } else {
        if ($self->{spf_result} eq "fail") {
            $spf_fail += 1;
            $rep -= 1;
        } elsif ($self->{spf_result} eq "pass") {
            $rep += 1;
            $spf_pass += 1;
        }
        if($rep > 100){
            $rep = 100;
        } elsif($rep < -100) {
            $rep = -100;
        }
    }

    $pdh = $self->{db}->prepare($self->{spf}->{set});
    $pdh->execute($spf_pass, $spf_fail, $self->{from}, $self->{env_from}); 
    $pdh->finish;

    $rep = sprintf("%.1f", $rep);

    return $rep;
}

sub calc_dkim_rep {
    my ($self) = @_;
    my $rep = 0;
    my ($dkim_pass, $dkim_pass_au, $dkim_unknown, $dkim_fail) = qw(0 0 0 0);
    #### DKIM Reputation
    # This reputation is based on how many "pass" vs. "pass au" vs. "fail" vs. "unknown" results there are.
    # Unknown = -1
    # Fail = -2
    # Pass = +1
    # Pass AU = +2

    my $pdh = $self->{db}->prepare($self->{dkim}->{get});
    $pdh->execute($self->{from}, $self->{env_from});
    while (my $row = $pdh->fetchrow_hashref) {
        $dkim_pass += $row->{dkim_pass};
        $dkim_pass_au += $row->{dkim_pass_au};
        $dkim_unknown += $row->{dkim_unknown};
        $dkim_fail += $row->{dkim_fail};
        $rep += $row->{dkim_pass} + ($row->{dkim_pass_au} * 2);
        $rep -= $row->{dkim_unknown} + ($row->{dkim_fail} * 2);
    }
    $pdh->finish;

    # If there is no DKIM reputation, we have to make something up
    if($rep == 0) {
        if ($self->{dkim_result} eq "fail") {
            $dkim_fail += 1;
            $rep -= 10;
        } elsif ($self->{dkim_result} eq "pass au") {
            $dkim_pass_au += 1;
            $rep += 2.5;
        } elsif ($self->{dkim_result} eq "unknown") {
            $dkim_unknown += 1;
            $rep -= 5;
        } else {
            $dkim_pass += 1;
        }
    } else {
        if ($self->{dkim_result} eq "fail") {
            $dkim_fail += 1;
            $rep -= 2;
        } elsif ($self->{dkim_result} eq "pass au") {
            $dkim_pass_au += 1;
            $rep += 2;
        } elsif ($self->{dkim_result} eq "unknown") {
            $dkim_unknown += 1;
            $rep -= 1;
        } else {
            $dkim_pass += 1;
            $rep += 1;
        }
        if($rep > 100) {
            $rep = 100;
        } elsif($rep < -100) {
            $rep = -100;
        }
    }

    $pdh = $self->{db}->prepare($self->{dkim}->{set});
    $pdh->execute($dkim_pass, $dkim_pass_au, $dkim_fail, $dkim_unknown, $self->{from}, $self->{env_from}); 
    $pdh->finish;

    $rep = sprintf("%.1f", $rep);

    return $rep;
}

sub calc_address_rep {
    my ($self) = @_;
    my $rep = 0;
    my ($ham, $spam) = qw(0 0);
    #### Address Reputation
    # This Reputation is based on the number of mails that have been considered clean vs. spam
    # If the SpamAssassin Score is greater than 20, we mark it as 2 spams
    # If the SpamAssassin Score is greater than or equal to 5, we mark it as 1 spam
    # If the SpamAssassin Score is less than 5, we mark is a 1 clean
    # False Positive/Negative Reports would also feed this, but modify both by 2 spam/clean mails

    my $pdh = $self->{db}->prepare($self->{address}->{get});
    $pdh->execute($self->{from}, $self->{env_from});
    while (my $row = $pdh->fetchrow_hashref) {
        $ham += $row->{ham};
        $rep += $row->{ham};
        $spam += $row->{spam};
        $rep -= $row->{spam};
    }
    $pdh->finish;

    # If there is no Address Reputation, we have to make something up
    # Let's assume they are fairly guilty if it's their first mail.
    if($rep == 0) {
        if($self->{sa_score} > 20) {
            $spam += 2;
            $rep -= 10;
        } elsif ($self->{sa_score} >= 5) {
            $spam += 1;
            $rep -= 5;
        } else {
            $ham += 1;
            $rep += 5;
        }
    } else {
        if($self->{sa_score} > 20) {
            $spam += 2;
            $rep -= 2;
        } elsif ($self->{sa_score} >= 5) {
            $spam += 1;
            $rep -= 1;
        } else {
            $ham += 1;
            $rep += 1;
        }
        if($rep > 100) {
            $rep = 100;
        } elsif($rep < -100){
            $rep = -100;        
        }
    }

    $pdh = $self->{db}->prepare($self->{address}->{set});
    $pdh->execute($spam, $ham, $self->{from}, $self->{env_from}); 
    $pdh->finish;

    $rep = sprintf("%.1f", $rep);

    return $rep;
}

sub get_ip_rep {
    my ($self) = shift;
    my $rep = 0;

    my ($a,$b,$c,$d) = split /\./, $self->{client_addr};
    my $reverse_addr = "$d.$c.$b.$a";
    my $dnsbl_count = 0;

    my $resolver = Net::DNS::Resolver->new or die($!);
    $resolver->tcp_timeout( 5 );
    $resolver->udp_timeout( 5 );

    ## DNS TXT lookup for ip against rep.titanhq.com
    for my $dnsbl (@{$self->{ip}->{dnsbls}}) {
        my $trep = 0;
        $dnsbl_count += 1;
        my $query = "$reverse_addr.$dnsbl";
        if($dnsbl eq "rep.titanhq.com") {
            my $reply = $resolver->query( $query, 'TXT', 'IN' );
            if (defined($reply)) {
                foreach my $rr ($reply->answer) {
                    next unless $rr->type eq "TXT";
                    my $result = $rr->string;
                    if ($result =~ /Reputation=([\-0-9]+);/) {
                        $trep = $1;
                        last;
                    }
                }
            }
        } else {
            my $reply = $resolver->query( $query, 'A', 'IN' );
            if (defined($reply)) {
                foreach my $rr ($reply->answer) {
                    next unless $rr->type eq "A";
                    my $result = $rr->string;
                    if ($result =~ /127\.0\.\d+\.(\d+)/) {
                        $trep = $1;
                        last;
                    }
                }
            }
        }
        my ($upper, $lower) = $self->get_ip_rep_range($dnsbl);
        $rep += $self->normalize($upper, $trep, $lower) if $trep != 0 ;
    }
    $rep = $self->normalize($dnsbl_count * 100, $rep, $dnsbl_count * -100);
    $rep = sprintf("%.3f", $rep);

    return $rep;
}

sub get_ip_rep_range {
    my ($self, $dnsbl) = @_;
    my ($upper, $lower) = qw(1350 -1350);
    if($dnsbl eq "score.senderscore.org") {
        return (100, 0);
    } elsif ($dnsbl eq "rep.mailspike.net") {
        return (20, 10);
    }
    
    my $resolver = Net::DNS::Resolver->new or die($!);
    $resolver->tcp_timeout( 5 );
    $resolver->udp_timeout( 5 );

    my $reply = $resolver->query( "4.1.0.127.".$dnsbl, 'TXT', 'IN' );
    if (defined($reply)) {
        foreach my $rr ($reply->answer) {
            next unless $rr->type eq "TXT";
            my $result = $rr->string;
            if ($result =~ /Reputation=([\-0-9]+);/) {
                $upper = $1;
                last;
            }
        }
    }
    $reply = $resolver->query( "4.2.0.127.".$dnsbl, 'TXT', 'IN' );
    if (defined($reply)) {
        foreach my $rr ($reply->answer) {
            next unless $rr->type eq "TXT";
            my $result = $rr->string;
            if ($result =~ /Reputation=([\-0-9]+);/) {
                $lower = $1;
                last;
            }
        }
    }

    return ($upper, $lower);
}

sub normalize {
    my ($self, $top, $value, $bottom, $norm_top, $norm_bottom) = @_;
    $norm_top = 100 if !defined($norm_top);
    $norm_bottom = -100 if !defined($norm_bottom);

    my $norm_value;

    $norm_value = $norm_bottom + ($value - $bottom) * ($norm_top - $norm_bottom) / ($top - $bottom);

    $norm_value = $norm_top if $norm_value > $norm_top;
    $norm_value = $norm_bottom if $norm_value < $norm_bottom;

    return $norm_value;
}

1;
