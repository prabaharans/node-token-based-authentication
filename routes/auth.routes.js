const express = require('express')
const jwt = require('jsonwebtoken')
const bcrypt = require('bcrypt')
const Token = require("../models/Token");
const sendEmail = require("../utils/email/sendEmail");
const crypto = require("crypto");
const router = express.Router()
const userSchema = require('../models/User')
const authorize = require('../middlewares/auth')
const { check, validationResult } = require('express-validator')
require('dotenv').config();

const JWTSecret = process.env.JWT_SECRET;
const bcryptSalt = process.env.BCRYPT_SALT;
const clientURL = process.env.CLIENT_URL;

// Sign-up
router.post(
  '/register-user',
  [
    check('name')
      .not()
      .isEmpty()
      .isLength({ min: 3 })
      .withMessage('Name must be atleast 3 characters long'),
    check('email', 'Email is required').not().isEmpty(),
    check('password', 'Password should be between 5 to 8 characters long')
      .not()
      .isEmpty()
      .isLength({ min: 5, max: 8 }),
    check('userType', 'User Type is required').not().isEmpty(),
  ],
  (req, res, next) => {
    const errors = validationResult(req)
    console.log(req.body)

    if (!errors.isEmpty()) {
      return res.status(422).jsonp(errors.array())
    } else {
      bcrypt.hash(req.body.password, 10).then((hash) => {
        const user = new userSchema({
          name: req.body.name,
          email: req.body.email,
          password: hash,
          user_type: req.body.userType,
        })
        const token = jwt.sign({ id: user._id }, JWTSecret);
        user
          .save()
          .then((response) => {

            sendEmail(user.email,"Welcome Prabaharan'S family",{name: user.name},"./template/welcomeUser.handlebars");
            res.status(201).json({
              message: 'User successfully created!',
              result: response,
            })
          })
          .catch((error) => {
            res.status(500).json({
              error: error,
            })
          })
      })
    }
  },
)

// Sign-in
router.post('/signin', (req, res, next) => {
  let getUser
  userSchema
    .findOne({
      email: req.body.email,
    })
    .then((user) => {
      if (!user) {
        return res.status(401).json({
          message: 'Authentication failed',
        })
      }
      getUser = user
      return bcrypt.compare(req.body.password, user.password)
    })
    .then((response) => {
      if (!response) {
        return res.status(401).json({
          message: 'Authentication failed',
        })
      }
      let jwtToken = jwt.sign(
        {
          email: getUser.email,
          userId: getUser._id,
        },
        'longer-secret-is-better',
        {
          expiresIn: '1h',
        },
      )
      console.log(req.body.remember);
      // if (req.body.remember == true) {
      //   console.log("remember me, save cookie");

      //   res.cookie("cookieToken", jwtToken, { maxAge: 900000 }); //expires after 900000 ms = 15 minutes
      //   res.cookie("cookieId", getUser._id, { maxAge: 900000 }); //expires after 900000 ms = 15 minutes
      // }
      res.status(200).json({
        remember: req.body.remember,
        token: jwtToken,
        expiresIn: 3600,
        _id: getUser._id,
        message: 'LoggedIn successfully',
      })
    })
    .catch((err) => {
      if(res.headersSent !== true) {
        return res.status(401).json({
          message: 'Authentication failed',
        })
      }
    })
})

// Get Users
router.route('/').get((req, res, next) => {
  userSchema.find((error, response)=> {
    if (error) {
      return next(error)
    } else {
      return res.status(200).json(response)
    }
  })
})


// Get Single User
router.route('/user-profile/:id').get(authorize, (req, res, next) => {
  userSchema.findById(req.params.id, (error, data) => {
    if (error) {
      return next(error)
    } else {
      res.status(200).json({
        msg: data,
      })
    }
  })
})

// Update User
router.route('/update-user/:id').put((req, res, next) => {
  userSchema.findByIdAndUpdate(
    req.params.id,
    {
      $set: req.body,
    },
    (error, data) => {
      if (error) {
        return next(error)
      } else {
        res.json(data)
        console.log('User successfully updated!')
      }
    },
  )
})

// Delete User
router.route('/delete-user/:id').delete((req, res, next) => {
  userSchema.findByIdAndRemove(req.params.id, (error, data) => {
    if (error) {
      return next(error)
    } else {
      res.status(200).json({
        msg: data,
      })
    }
  })
})

// forgot-password
router.post('/forgot-password',
  [
    check('email', 'Email is required').not().isEmpty()
  ],
  async (req, res, next) => {
    // console.log("req", req.body.email);
    await userSchema
    .findOne({
      email: req.body.email,
    })
    .then(async (user) => {
      if (!user) {
        return res.status(401).json({
          message: 'Please enter valid email..',
        })
      }
      let token = await Token.findOne({ userId: user._id });
      if (token) token.deleteOne();
      let resetToken = crypto.randomBytes(32).toString("hex");
      const hash = await bcrypt.hash(resetToken, Number(bcryptSalt));
      console.log('user_id',user._id);
      console.log('hash',hash);
      await new Token({
        userId: user._id,
        token: hash,
        createdAt: Date.now(),
      }).save();

      const link = `${clientURL}/password-reset/${resetToken}/${user._id}`;
      sendEmail(user.email,"Password Reset Request",{name: user.name,link: link,},"./template/requestResetPassword.handlebars");
      return res.status(200).json({
        link: link,
        message: 'Please check your mail, we have sent mail to you for reset password',
      })
    })
    .catch((err) => {
      if(res.headersSent !== true) {
        return res.status(401).json({
          message: 'Please enter valid email.',
        })
      }
      console.log(err);
      process.exit(1);
    })
})

// valid-password-token
router.post('/valid-password-token',
  async (req, res) => {
    if (!req.body.resettoken) {
      return res
      .status(500)
      .json({ message: 'Token is required' });
    }
    if (!req.body.id) {
      return res
      .status(500)
      .json({ message: 'Id is required' });
    }
    const hash = await bcrypt.hash(req.body.resettoken, Number(bcryptSalt));

    const user = await Token.findOne({
      userId: req.body.id
    });
    console.log('hash');
    console.log(hash);
    if (!user) {
      return res
      .status(409)
      .json({ message: 'Invalid Id' });
    }
    bcrypt.compare(req.body.resettoken, user.token, function(err, result) {
      if (result) {
        userSchema.findOne({ _id: user.userId }).then(() => {
          res.status(200).json({ message: 'Token verified successfully.' });
        }).catch((err) => {
          return res.status(500).send({ msg: err.message });
        });
      } else {
        return res
        .status(409)
        .json({ message: 'Invalid URL' });
      }
    });
  }
)
// new-password
router.post('/new-password',
  async (req, res) => {
    if (!req.body.resettoken) {
      return res
      .status(500)
      .json({ message: 'Token is required' });
    }
    if (!req.body.id) {
      return res
      .status(500)
      .json({ message: 'Id is required' });
    }
    const hash = await bcrypt.hash(req.body.resettoken, Number(bcryptSalt));

    const user = await Token.findOne({
      userId: req.body.id
    });
    console.log('hash');
    console.log(hash);
    if (!user) {
      return res
      .status(409)
      .json({ message: 'Invalid Id' });
    }
    bcrypt.compare(req.body.resettoken, user.token, function(err, result) {
      if (!result) {
        return res
          .status(409)
          .json({ message: 'Token has expired' });
      }
    });

    userSchema.findOne({
      _id: user.userId
    }, function (err, userEmail, next) {
      if (!userEmail) {
        return res
          .status(409)
          .json({ message: 'User does not exist' });
      }
      return bcrypt.hash(req.body.newPassword, 10, (err, hash) => {
        if (err) {
          return res
            .status(400)
            .json({ message: 'Error hashing password' });
        }
        userEmail.password = hash;
        userEmail.save(function (err) {
          if (err) {
            return res
              .status(400)
              .json({ message: 'Password can not reset.' });
          } else {
            Token.remove();
            return res
              .status(201)
              .json({ message: 'Password reset successfully' });
          }

        });
      });
    });
  }
)
module.exports = router
