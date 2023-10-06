const express = require('express')
const { v4: uuid } = require("uuid");
const session = require('express-session')
const fileStore = require('session-file-store')(session)
const bodyParse = require('body-parser')
const passport = require('passport')
const localStrategy = require('passport-local').Strategy
const axios = require('axios')
const bcrypt = require('bcrypt-nodejs');

const app = express()

require('dotenv').config()
const PORT = process.env.PORT || 3001

passport.use(new localStrategy(
  { usernameField: 'email' },
  (email:any, password:any, done:any) => {
    axios.get(`http://localhost:5000/users?email=${email}`)
    .then((res: any) => {
      const user = res.data[0]
      if (!user) {
        return done(null, false, { message: 'Invalid credentials.\n' });
      }
      if (!bcrypt.compareSync(password , user.password)) {
        return done(null, false, { message: 'Invalid credentials.\n' });
      }
      return done(null, user);
    })
    .catch((error: any) => done(error));
  }
))

passport.serializeUser((user:any, done: any) => {
  console.log("Inside serializeUser callBack. User id is save to session")
  done(null, user.id)
})

passport.deserializeUser((id: any, done: any) => {
  axios.get(`http://localhost:5000/users/${id}`)
  .then((res: any) => done(null, res.data) )
  .catch((error: any) => done(error, false))
});

app.use(bodyParse.urlencoded({extended: false}))
app.use(bodyParse.json())
app.use(session({
  genid: (req: any) => {
    console.log('Inside middleware session express')
    console.log(req.sessionID)
    return uuid()
  },
  store: new fileStore(),
  secret: 'ohshhhhhhhht',
  resave: false,
  saveUninitialized: true
}))
app.use(passport.initialize())
app.use(passport.session())


app.get('/', (req: any, res: any) => {
  console.log('Inside the homepage callback function')
  console.log(req.sessionID)
  res.send(`You hit home page!\n`)
  });

app.get('/login', (req: any, res: any) => {
  console.log('Inside the GET login route')
  console.log(req.sessionID)
  res.send('GET LOGIN')
})

app.post('/login', (req: any, res: any, next: any) => {
  console.log('Inside the POST login route');
  passport.authenticate('local', (err: any, user: any, info:any) => {
    console.log('Inside passport.authenticate() callback');
    console.log(`req.session.passport:${JSON.stringify(req.session.passport)}`)
    console.log(`req.user:${JSON.stringify(req.user)}`)

    if(info) {return res.send(info.message)}
    if (err) { return next(err); }
    if (!user) { return res.redirect('/login'); }
    req.login(user, (err: any) => {
      if (err) { return next(err); }
      return res.redirect('/authrequired');
    })
  })(req, res, next);
})

app.get('/authrequired', (req: any, res: any) => {
  console.log('Inside GET /authrequired callback')
  console.log(`User authenticated? ${req.isAuthenticated()}`)
  if(req.isAuthenticated()) {
    res.send('you hit the authentication endpoint\n')
  } else {
    res.redirect('/')
  }
})
  
app.listen(PORT, () => {
    console.log('This server is running at port: ' + PORT)
})