var express = require("express");
var router = express.Router();
const { db } = require("../mongo.js");
const { uuid } = require("uuidv4");
const { hash, compare } = require("bcryptjs");
const { sign, verify } = require("jsonwebtoken");
const jwt = require("jsonwebtoken");
const { endsWith } = require("lodash");
const { token } = require("morgan");
require("dotenv").config();

/* GET users listing. */
router.get("/", function (req, res, next) {
	res.send("respond with a resource");
});

//get message route from the server that will tell if the user is an admin or not
// the user will be an admin if the user's email ends with @codeimmersives2022.com
router.get("/message", async (req, res) => {
	const token = req.header("Authorization").replace("Bearer ", "");
	const decoded = jwt.verify(token, process.env.JWT_SECRET_KEY);
	const user = await db().collection("users").findOne({ _id: decoded._id });
	if (user.email.endsWith("codeimmersives.com")) {
		res.send({
			message: "You are an admin",
			email: user.email,
		});
	} else {
		res.send({
			message: "You are not an admin",
			email: user.email,
		});
	}
});

router.post("/register", async (req, res) => {
	const { email, password } = req.body;
	const hashedPassword = await hash(password, 5);
	const user = {
		_id: uuid(),
		email,
		password: hashedPassword,
	};
	await db().collection("users").insertOne(user);
	res.json(user);
});

//login with email and password and get a token
router.post("/login", async (req, res) => {
	const { email, password } = req.body;
	const user = await db().collection("users").findOne({
		email,
	});
	if (!user) {
		return res.status(400).json({
			success: false,
			error: "User not found",
		});
	}
	const validPassword = await compare(password, user.password);
	if (!validPassword) {
		return res.status(400).json({
			error: "Invalid password",
		});
	}
	const userdata = {
		_id: user._id,
		email: user.email,
	};
	const token = sign(
		{
			_id: user._id,
			Date: new Date(),
		},
		process.env.JWT_SECRET_KEY,
		{
			expiresIn: "24h",
		}
	);
	res.json({
		success: true,
		token,
		email: user.email,
	});
});

module.exports = router;
