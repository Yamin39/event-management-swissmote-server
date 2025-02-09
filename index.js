const { MongoClient, ServerApiVersion } = require("mongodb");
const port = process.env.PORT || 5000;
const express = require("express");
const cors = require("cors");
const app = express();
require("dotenv").config();
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");

// middleware
app.use(cors());
app.use(express.json());

const verifyToken = (req, res, next) => {
  console.log("in verify token", req.headers?.authorization);

  if (!req.headers?.authorization) {
    return res.status(401).send({ message: "Unauthorized" });
  }

  const token = req.headers?.authorization?.split(" ")[1];

  console.log(token);

  jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (error, decoded) => {
    if (error) {
      return res.status(401).send({ message: "Unauthorized" });
    }
    req.decoded = decoded;
    next();
  });
};

const verifyAdmin = (req, res, next) => {
  if (req.decoded.role !== "admin") {
    return res.status(401).send({ message: "Unauthorized" });
  }
  next();
};

const uri = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASS}@cluster0.6fu63x8.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0`;

const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
});
async function run() {
  try {
    // collections
    const usersCollection = client.db("emsJobTaskDB").collection("users");
    const eventsCollection = client.db("emsJobTaskDB").collection("events");

    // auth

    // get auth data
    app.get("/auth", verifyToken, async (req, res) => {
      const email = req.decoded.email;
      const query = { email };
      const result = await usersCollection.findOne(query);

      res.send({
        _id: result?._id,
        fullName: result?.fullName,
        email: result?.email,
        role: result?.role,
      });
    });

    // Register user
    app.post("/auth/register", async (req, res) => {
      const user = req.body;
      const isExist = await usersCollection.findOne({ email: user.email });
      if (isExist) {
        res.send({ result: { message: "User already exist", insertedId: null } });
        return;
      }

      const hashedPassword = await bcrypt.hash(user.password, 10);
      user.password = hashedPassword;

      const token = jwt.sign(user, process.env.ACCESS_TOKEN_SECRET, {
        expiresIn: "10d",
      });

      const result = await usersCollection.insertOne(user);
      res.send({ result, token });
    });

    // user login
    app.post("/auth/login", async (req, res) => {
      const password = req.body.password;
      const user = await usersCollection.findOne({ email: req.body.email });
      if (!user) {
        res.send({ result: { message: "Email or Password is wrong", isLogin: false } });
        return;
      }

      const passwordCompare = await bcrypt.compare(password, user.password);
      if (!passwordCompare) {
        res.send({ result: { message: "Email or Password is wrong", isLogin: false } });
        return;
      }

      const token = jwt.sign(user, process.env.ACCESS_TOKEN_SECRET, {
        expiresIn: "10d",
      });

      res.send({ result: { isLogin: true }, token });
    });

    // guest login
    app.post("/auth/guest-login", async (req, res) => {
      const user = await usersCollection.findOne({ email: "guest@gmail.com" });

      const token = jwt.sign(user, process.env.ACCESS_TOKEN_SECRET, {
        expiresIn: "10d",
      });

      res.send({ result: { isLogin: true }, token });
    });

    // events

    app.post("/events", verifyToken, verifyAdmin, async (req, res) => {
      const event = req.body;
      const result = await eventsCollection.insertOne(event);
      res.send({ result });
    });

    // Send a ping to confirm a successful connection
    await client.db("admin").command({ ping: 1 });
    console.log("Pinged your deployment. You successfully connected to MongoDB!");
  } finally {
    // await client.close();
  }
}
run().catch(console.dir);

app.get("/", (req, res) => {
  res.send("Event Management - Swissmote - server is running");
});

app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});
