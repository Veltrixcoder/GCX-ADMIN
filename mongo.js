const { MongoClient, ServerApiVersion } = require('mongodb');

const uri = "mongodb+srv://bob17040246:shashwat1234@cluster0.u1ox3.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0";
const dbName = 'GCX';

const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  }
});

let db;

async function connectToMongo() {
  if (!db) {
    try {
      console.log("Attempting to connect to MongoDB Atlas...");
      await client.connect();
      db = client.db(dbName);
      console.log("Connected to MongoDB Atlas!");
    } catch (err) {
      console.error("Failed to connect to MongoDB Atlas:", err);
      throw err;
    }
  }
  return db;
}

module.exports = { connectToMongo }; 