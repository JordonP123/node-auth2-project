const router = require("express").Router();
const { checkUsernameExists, validateRoleName } = require('./auth-middleware');
const { JWT_SECRET } = require("../secrets"); // use this secret!
const bcrypt = require('bcryptjs')
const User = require('../users/users-model')
const jwt = require('jsonwebtoken')

router.post("/register", validateRoleName, async(req, res, next) => {
  
  /**
    [POST] /api/auth/register { "username": "anna", "password": "1234", "role_name": "angel" }

    response:
    status 201
    {
      "user"_id: 3,
      "username": "anna",
      "role_name": "angel"
    }
   */

   try{ 
    let user = req.body
    const hash = bcrypt.hashSync(user.password, 8)
    user.password = hash
    
    const addUser = await User.add(user)
    res.status(201).json(addUser)
  } catch(err){
    next(err)
  }



});


router.post("/login", checkUsernameExists, async(req, res, next) => {
  try{
    let{ username } = req.body
    const [findUser] = await User.findBy({ username })
    console.log(findUser)
      const token = buildToken(findUser)
      res.status(200).json({
        message: `${req.body.username} is back!`,
        token: token
      })
  } catch (err){
    res.status(500).json({
      message: err.message
    })
  }
  /**
    [POST] /api/auth/login { "username": "sue", "password": "1234" }

    response:
    status 200
    {
      "message": "sue is back!",
      "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.ETC.ETC"
    }

    The token must expire in one day, and must provide the following information
    in its payload:

    {
      "subject"  : 1       // the user_id of the authenticated user
      "username" : "bob"   // the username of the authenticated user
      "role_name": "admin" // the role of the authenticated user
    }
   */
});

function buildToken(user){
  const payload = {
    subject: user.user_id,
    username: user.username,
    role_name: user.role_name
  }
  const options = {
    expiresIn: '1d'
  }
  return jwt.sign(payload, JWT_SECRET, options)
}

module.exports = router;
