const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const { JWT_SECRET } = require("../secrets");
const { tokenBuilder } = require("./tokenbuilder");
const Users = require("./../users/users-model");

const restricted = (req, res, next) => {
  const token = req.headers.authorization;

  if (!token) {
    return next({ status: 401, message: "Token required" });
  }

  jwt.verify(token, JWT_SECRET, (err, decodedToken) => {
    if (err) {
      return next({ status: 401, message: "Token invalid" });
    }

    req.decodedToken = decodedToken;
    return next();
  });
};

const only = (role_name) => (req, res, next) => {
  if (req.decodedToken.role_name === role_name) {
    next();
  } else {
    next({ status: 403, message: "This is not for you" });
  }
};

const checkUsernameExists = async (req, res, next) => {
  const validUsername = await Users.findBy({ username: req.body.username });
  if (!validUsername) {
    next({ status: 401, message: "Invalid credentials" });
  } else {
    next();
  }
};

const validateRoleName = (req, res, next) => {
  const role_name = req.body.role_name;

  if (!role_name || role_name.trim().length < 1) {
    req.body.role_name = "student";
    next();
  } else {
    const trimmedRole = req.body.role_name.trim().toLowerCase();
    if (trimmedRole === "admin") {
      next({ status: 422, message: "Role name can not be admin" });
    } else if (trimmedRole.length > 32) {
      next({
        status: 422,
        message: "Role name can not be longer than 32 chars",
      });
    } else {
      req.body.role_name = trimmedRole;
      next();
    }
  }
};

const checkPasswordCorrect = async (req, res, next) => {
  let { username, password } = req.body;

  const validUser = await Users.findBy({ username: username });

  if (validUser && bcrypt.compareSync(password, validUser.password)) {
    const token = tokenBuilder(validUser);
    req.token = token;
    next();
  } else {
    next({ status: 401, message: "Invalid Credentials" });
  }
};

const hashThePassword = (req, res, next) => {
  const rounds = process.env.BCRYPT_ROUNDS || 8;
  const hash = bcrypt.hashSync(req.body.password, rounds);

  req.body.password = hash;
  next();
};

module.exports = {
  restricted,
  checkUsernameExists,
  validateRoleName,
  only,
  checkPasswordCorrect,
  hashThePassword,
};
