# Reputation-SpamScanner
A custom spamscanner for Amavis

Determines spam score based on the reputation of:
- The IP address of the sender (from third-party sources)
- The number of valid/invalid DKIM results
- The number of valid/invalid SPF results
- The number of Spam/Ham messages sent by the sender.
