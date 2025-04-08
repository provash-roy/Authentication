const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const passport = require("passport");

const secretKey = "your-very-secret-key"; // Secrate key
const PORT = 4000;
const MONGO_URL = "mongodb://localhost:27017/pasportJWBDB";
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
  const users = await User.find().select("-password");

  res.send(users);
});

app.post("/register", async (req, res) => {
  try {
    const { username, password } = req.body;

    // Hashing Password
    const hashedPassword = await bcrypt.hash(password, saltRounds);

    // Creating New User
    const newUser = new User({
      username,
      password: hashedPassword,
    });

    // Save in Database
    await newUser.save();

    res.status(201).json(newUser);
  } catch (err) {
    res.status(500).send({ message: err.message });
  }
});

// Login and generate token
app.post("/login", async (req, res) => {
  try {
    const { username, password } = req.body;

    // Find user in Database
    const user = await User.findOne({ username });

    if (!user) {
      return res.status(404).json({ message: "User is not found" });
    }

    // Cheaking Password
    const isMatch = await bcrypt.compare(password, user.password);

    if (!isMatch) {
      return res.status(401).json({ message: "Wrong Password" });
    }

    // Data (Payload)
    const payload = {
      id: user._id,
      username: user.username,
    };

    //Token Generate
    const token = jwt.sign(payload, secretKey, { expiresIn: "1h" });

    res
      .status(200)
      .json({ message: "Login Successfull", token: "Bearer " + token, user });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// Middleware to verify token
const { Strategy: JwtStrategy, ExtractJwt } = require("passport-jwt");

const opts = {
  jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
  secretOrKey: secretKey,
};

passport.use(
  new JwtStrategy(opts, async (jwt_payload, done) => {
    try {
      const user = await User.findById(jwt_payload.id);
      if (user) {
        return done(null, user);
      }
      return done(null, false);
    } catch (err) {
      return done(err, false);
    }
  })
);

app.use(passport.initialize());

app.get("/profile",passport.authenticate("jwt", { session: false }),
  (req, res) => {
    res.status(200).json({
      message: "✅ Token is verified",
      user: req.user,
    });
  }
);

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
