// Run this locally whenever you want to change the admin password:
//   node hash-password.js "YourNewPassword"
// Copy the printed hash into your .env file as ADMIN_PASSWORD_HASH.
// Nobody needs to see your plaintext password to do this — it never
// leaves your own machine.

const bcrypt = require('bcryptjs');

const password = process.argv[2];
if (!password) {
  console.log('Usage: node hash-password.js "YourPassword"');
  process.exit(1);
}
console.log(bcrypt.hashSync(password, 12));
