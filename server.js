const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
PORT = 4000;
MONGO_URL = "mongodb://localhost:27017/pasportJWBDB";
const saltRounds = 10;
const app = express();

//Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

//Dataabase connection
mongoose
  .connect(MONGO_URL)
  .then(() => {
    console.log("db is connected");
  })
  .catch((error) => {
    console.log(error.message);
    process.exit(1);
  });

//Schema and Model
const userSchema = mongoose.Schema({
  username: {
    type: String,
    required: true,
    unique: true,
  },
  password: {
    type: String,
    required: true,
  },
  createdOn: {
    type: Date,
    default: Date.now,
  },
});

const User = mongoose.model("user", userSchema);

//Home Routes
app.get("/", (req, res) => {
  res.send("<h2>Welcome to Server</h2>");
});

// All users
app.get("/users", async (req, res) => {
  const users = await User.find();
  res.send(users);
});

app.post("/register", async (req, res) => {
  try {
    const { username, password } = req.body;

    // পাসওয়ার্ড হ্যাশ করো
    const hashedPassword = await bcrypt.hash(password, saltRounds);

    // নতুন ইউজার তৈরি করো
    const newUser = new User({
      username,
      password: hashedPassword,
    });

    // ডাটাবেজে সেভ করো
    await newUser.save();

    res.status(201).json(newUser);
  } catch (err) {
    res.status(500).send({ message: err.message });
  }
});

app.post("/login", async (req, res) => {
  try {
    const { username, password } = req.body;

    // ইউজার খোঁজো ডাটাবেজে
    const user = await User.findOne({ username });

    if (!user) {
      return res.status(404).json({ message: "⚠️ ইউজার পাওয়া যায়নি" });
    }

    // পাসওয়ার্ড যাচাই করো
    const isMatch = await bcrypt.compare(password, user.password);

    if (!isMatch) {
      return res.status(401).json({ message: "❌ পাসওয়ার্ড ভুল" });
    }

    res.status(200).json({ message: "✅ লগইন সফল", user });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});


//Resource not found
app.use((req, res, next) => {
  res.status(404).json({
    message: "route not found",
  });
});

//Server error
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).send("Something broke!");
});

app.listen(PORT, () => {
  console.log(`Sever is running at http://localhost:${PORT}`);
});
