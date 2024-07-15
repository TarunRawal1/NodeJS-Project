const mongoose = require("mongoose");
const express = require("express");
const jwt = require("jsonwebtoken");
const Joi = require("joi");
const bp = require("body-parser");
const app = express();
const bcrypt = require("bcrypt");
app.use(bp.urlencoded({ extended: false }));

async function JWTAuth(req, res, next) {
  const token = req.headers["authorization"];
  console.log("token", token);
  if (!token) return res.status(400).send("Invalid token.");
  try {
    const fin = jwt.verify(token, "jwtPrivateKey");
    console.log("fin", fin);
    next();
  } catch (err) {
    return res.status(400).send("Invalid token.");
  }
}

async function JWT(payload) {
  const token = jwt.sign({ email: payload }, "jwtPrivateKey");
  return token;
}

async function admincheck(req, res, next) {
  const admin = await Employee.findOne({
    email: req.query.email,
  });
  if (!admin) return res.send("User not found.");
  if (!admin.Admin)
    return res
      .status(400)
      .send("You are not authorised to Perform this operation.");
  else next();
}
async function hashPassword(password) {
  const salt = await bcrypt.genSalt(10);
  return await bcrypt.hash(password, salt);
}
function validateEmployee(employee) {
  const empschema = Joi.object({
    name: Joi.string().min(3).max(20).required(),
    email: Joi.string().email().min(5).max(70).required(),
    password: Joi.string().min(8).max(20).required(),
  });
  return empschema.validate(employee);
}

async function authorisation(req, res, next) {
  const email = req.query.email;
  const user = await Employee.findOne({ email: email });
  if (user) return res.status(400).send("User already registered.");
  else next();
}

// Connect to MongoDB
mongoose
  .connect("mongodb://localhost/Employees")
  .then(() => console.log("Connected to MongoDB..."))
  .catch((err) => console.error("Could not connect to MongoDB..."));

const empschema = new mongoose.Schema({
  name: String,
  email: String,
  password: String,
  Admin: String,
  jwt: String,
});

const Employee = mongoose.model("Employee", empschema);

app.get("/register", authorisation, async (req, res) => {
  const { error } = validateEmployee(req.query);
  if (error) return res.status(400).send(error.details[0].message);
  const name = req.query.name;
  const email = req.query.email;
  const password = await hashPassword(req.query.password);
  const jwt = await JWT(email);
  const employee = new Employee({
    name: name,
    email: email,
    password: password,
    jwt: jwt,
  });
  const result = await employee.save();
  res
    .header("key", jwt)
    .send(`Welcome ${result.name}! You have been registered successfully.`);
});
app.get("/login", async (req, res) => {
  const email = req.query.email;
  const password = req.query.password;
  const user = await Employee.findOne({
    email: email,
  });
  if (!user) return res.status(400).send("Invalid email or password.");
  const validPassword = await bcrypt.compare(password, user.password);
  if (!validPassword) return res.send("Invalid email or password.");
  res.sendFile("/Viewall.html", { root: __dirname });
});
app.get("/delete", async (req, res) => {
  const email = req.query.email;
  const user = await Employee.findOne({ email: email });
  if (!user) {
    return res.status(404).send("User not found.");
  }
  if (user.Admin) {
    return res.send("Cannot delete an admin record.");
  }
  await Employee.deleteOne({ email: email });
  res.send("User deleted successfully.");
});
app.get("/viewall", [admincheck, JWTAuth], async (req, res) => {
  const employees = await Employee.find().select("name email -_id");
  res.send(employees);
});
app.post("/update", async (req, res) => {
  const email = req.body.email;
  const name = req.body.name;
  const password = req.body.password;
  const user = await Employee.findOne({ email: email });
  if (!user) return res.status(404).send("User not found.");
  user.name = name;
  user.password = await hashPassword(password);
  await user.save();
  res.send("User updated successfully.");
});

app.listen(7000, () => console.log("Server is running on port 7000..."));
