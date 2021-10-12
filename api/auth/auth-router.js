const router = require("express").Router();
const {
  checkUsernameExists,
  validateRoleName,
  checkPasswordCorrect,
  hashThePassword,
} = require("./auth-middleware");
const Users = require("./../users/users-model");

router.post(
  "/register",
  validateRoleName,
  hashThePassword,
  (req, res, next) => {
    Users.add(req.body)
      .then((userWithHash) => {
        res.status(201).json(userWithHash);
      })
      .catch(next);
  }
);

router.post(
  "/login",
  checkUsernameExists,
  checkPasswordCorrect,
  (req, res, next) => {
    try {
      res.status(200).json({
        message: `${req.body.username} is back!`,
        token: req.token,
      });
    } catch (err) {
      next(err);
    }
  }
);

module.exports = router;
