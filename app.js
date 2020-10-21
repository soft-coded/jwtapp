require("dotenv").config()
const express=require("express")
const jwt=require("jsonwebtoken")

const app=express()
app.use(express.json()) // bodyparser.json basically - to parse json data
let refreshTokens=[] // normally this would be stored in the database

// this will be retrieved from the database
const posts=[{username: "A",title: "Post 1"}, {username: "B", title: "Post 2"}]

app.get("/login", (req, res)=>{
  // authenticate User
  const user={name: req.body.username}
  const accessToken=generateAccessToken(user)
  const refreshToken=jwt.sign(user, process.env.REFRESH_TOKEN_SECRET)
  refreshTokens.push(refreshToken) // this is where the refresh token will be stored in the database
  res.json({accessToken: accessToken, refreshToken: refreshToken}) // send to the client to store in the browser for access across multiple servers
})

app.get("/posts", authenticateToken, (req, res) => {
  res.json(posts.filter(post=>post.username===req.user.name))
})

app.post("/token", (req,res)=>{
  const refreshToken = req.body.token // will be received with the request
  if(!refreshToken) return res.sendStatus(401) // unauthorised
  if(!refreshTokens.includes(refreshToken)) return res.sendStatus(403) // forbid the user from doing stuff if not logged in
  jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET, (err, user) =>{
    if(err) return res.sendStatus(403) // forbidden
    const accessToken=generateAccessToken({name: user.name})
    res.json({accessToken: accessToken}) // to be stored on the client side
  })
})

app.post("/logout", (req,res)=>{
  // remove the refresh token from the array
  refreshTokens=refreshTokens.filter(token=>token!==req.body.token)
  res.send("ok")
})


function authenticateToken(req, res, next) {
  // get the token
  const token=req.body.token
  if (!token) return res.sendStatus(401) // unauthorised

  jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err,user)=>{
    if (err) return res.sendStatus(403)
    req.user = user
    next()
  })
}
// a simple function to get an access token
function generateAccessToken(user) {
  return jwt.sign(user, process.env.ACCESS_TOKEN_SECRET, {expiresIn: "15m"})
}

app.listen(3000)