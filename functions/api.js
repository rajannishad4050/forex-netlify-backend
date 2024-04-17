const express = require("express");
const serverless = require("serverless-http");
const app = express();
const router = express.Router();
require("dotenv").config();
const cors = require("cors");
const port = 4000;
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const mongoose = require("mongoose");

// Connect to MongoDB
mongoose
  .connect(process.env.MONGODB_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  })
  .then(() => console.log("Connected to MongoDB"))
  .catch((err) => console.error("Error connecting to MongoDB", err));

// Define User model
const userSchema = new mongoose.Schema({
  email: String,
  username: String,
  password: String,
  currencies: [{ currency: String, amount: Number }],
});

const User = mongoose.model("User", userSchema);

app.use(express.json());
app.use(cors());

router.get("/", (req, res) => {
  res.send("App is running..");
});

// Middleware to verify JWT token
const verifyToken = (req, res, next) => {
  const token = req.header("Authorization");
  if (!token) {
    return res.status(401).json({ message: "No token, authorization denied" });
  }
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch (error) {
    res.status(401).json({ message: "Invalid token" });
  }
};

router.post("/register", async (req, res) => {
  const { email, username, password } = req.body;
  try {
    //check if email exists already
    const existingEmail = await User.findOne({ email });
    if (existingEmail) {
      return res.status(400).json({ message: "email already exists" });
    }

    // Check if user already exists
    const existingUser = await User.findOne({ username });
    if (existingUser) {
      return res.status(400).json({ message: "user already exists" });
    }
    // Hash the password
    const hashedPassword = await bcrypt.hash(password, 10);
    // Save the new user to MongoDB
    const newUser = new User({ email, username, password: hashedPassword });
    await newUser.save();
    const token = jwt.sign({ username }, process.env.JWT_SECRET, {
      expiresIn: "12h",
    });
    res.status(201).json({ message: "User registered successfully", token });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

router.post("/login", async (req, res) => {
  const { username, password } = req.body;
  try {
    // Find user by username
    const user = await User.findOne({ username });
    if (!user) {
      return res.status(401).json({ message: "username does not exist" });
    }
    // Check password
    const passwordMatch = await bcrypt.compare(password, user.password);
    if (!passwordMatch) {
      return res.status(401).json({ message: "password is incorrect" });
    }
    // Generate JWT token
    const token = jwt.sign({ username }, process.env.JWT_SECRET, {
      expiresIn: "12h",
    });
    res.json({ token });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

router.get("/currencies", verifyToken, async (req, res) => {
  try {
    // Find the user by username
    const user = await User.findOne({ username: req.user.username });
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }
    // Return the user's currencies
    res.json(user.currencies);
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

// Add currency for a user
router.post("/currencies", verifyToken, async (req, res) => {
  const { currency, amount } = req.body;

  if (
    currency === undefined ||
    currency === null ||
    amount === undefined ||
    amount === null
  ) {
    return res
      .status(400)
      .json({ message: "Invalid JSON format in the request body" });
  }

  try {
    const user = await User.findOne({ username: req.user.username });
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }
    user.currencies.push({ currency, amount });
    await user.save();
    res.status(201).json({ message: "Currency added successfully" });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

// Update currency for a user
router.put("/currencies/:currency", verifyToken, async (req, res) => {
  const { currency } = req.params;
  const { amount } = req.body;
  try {
    const user = await User.findOne({ username: req.user.username });
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }
    const currencyIndex = user.currencies.findIndex(
      (curr) => curr.currency === currency
    );
    if (currencyIndex === -1) {
      return res.status(404).json({ message: "Currency not found" });
    }
    user.currencies[currencyIndex].amount = amount;
    await user.save();
    res.json({ message: "Currency updated successfully" });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

// Delete currency for a user
router.delete("/currencies/:currency", verifyToken, async (req, res) => {
  const { currency } = req.params;
  try {
    const user = await User.findOne({ username: req.user.username });
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }
    user.currencies = user.currencies.filter(
      (curr) => curr.currency !== currency
    );
    await user.save();
    res.json({ message: "Currency deleted successfully" });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

app.use("/.netlify/functions/api", router);
module.exports.handler = serverless(app);
