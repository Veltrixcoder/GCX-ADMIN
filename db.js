const { connectToMongo } = require('./mongo');

// Returns the MongoDB database instance
async function getDb() {
  return await connectToMongo();
}

module.exports = {
  getDb
}; 