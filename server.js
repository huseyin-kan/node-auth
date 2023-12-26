const fs = require('fs');
const path = require('path')
const https = require('https')
const helmet = require('helmet')
const express = require('express')
const passport = require('passport')
const { verify } = require('crypto')
const cookieSession = require('cookie-session')
const {Strategy} =  require('passport-google-oauth20');


require('dotenv').config()

const PORT = 3000


const config = {
    CLIENT_ID: process.env.CLIENT_ID,
    CLIENT_SECRET: process.env.CLIENT_SECRET,
    COOKIE_KEY_1: process.env.COOKIE_KEY_1,
    COOKIE_KEY_2: process.env.COOKIE_KEY_2
}

const AUTH_OPTIONS = {
    callbackURL:'/auth/google/callback',
    clientID: config.CLIENT_ID,
    clientSecret: config.CLIENT_SECRET
}

const verifyCallback = (accessToken, refreshToken, profile, done) =>{
    console.log('Google Profile',profile);
    done(null,profile)
}

passport.use(new Strategy(AUTH_OPTIONS, verifyCallback))

//Save the session to the cookie
passport.serializeUser((user,done) =>{
    done(null,user.id)
})
//Read the session from the cookie
passport.deserializeUser((id,done)=>{
    done(null, id)
})

const app = express()

app.use(helmet())
app.use(cookieSession({
    name:'session',
    maxAge:24*60*60*1000,
    keys: [config.COOKIE_KEY_1,config.COOKIE_KEY_2],
    secure:true
}))
app.use(passport.initialize())
app.use(passport.session())

const checkLoggedIn = (req, res, next) =>{
    const isLoggedIn = req.user && req.isAuthenticated()
    if(!isLoggedIn){
        return res.status(401).json({
            error: 'You must log in'
        })
    }
    next()
}

app.get('/auth/google', passport.authenticate('google',{
    scope:['email']
}))

app.get('/auth/google/callback', 
passport.authenticate('google',{
    failureRedirect:'/failure',
    successRedirect:'/',
    session:true
}), 
(req, res)=>{
    console.log('Google called us back');
})

app.get('/auth/logout', (req,res)=>{
    req.logout()//Removes req.user and clears any logged in sessions
    return res.redirect('/')
})

app.get('/failure',(req,res)=>{
    return res.send('Login failed')
})

app.get('/secret',checkLoggedIn,(req,res)=>{
    return res.send('Your personal secret value is 42')
})

app.get('/',(req,res)=>{
    res.sendFile(path.join(__dirname, 'public', 'index.html'))
})

https.createServer({
    key:fs.readFileSync('key.pem'),
    cert:fs.readFileSync('cert.pm'),
}, app).listen(PORT,()=>{
    console.log(`Listening on ${PORT}`);
})
