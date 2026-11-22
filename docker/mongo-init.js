// Runs only when the official MongoDB image initializes a fresh data volume.
// Deployment secrets are supplied by the container environment, never source.
const user = process.env.SECURE_SMTP_MONGO_USER;
const password = process.env.SECURE_SMTP_MONGO_PASSWORD;
if (!user || !password || user === process.env.MONGO_INITDB_ROOT_USERNAME) {
  throw new Error('Set a distinct application database user and password');
}
db.getSiblingDB('secure_smtp_pilot').createUser({
  user,
  pwd: password,
  roles: [{role: 'readWrite', db: 'secure_smtp_pilot'}],
});
