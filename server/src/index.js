require('dotenv/config');
const express = require('express');
const cookieparser = require('cookie-parser');
const cors = require('cors');
const { verify } = require('jsonwebtoken');
const { hash,compare } = require('bcryptjs');
const { urlencoded } = require('express');
const {fakeDb} = require("./fakeDb");
const { isAuth } = require('./isAuth.js');
const { createAccessToken,createRefreshToken,sendAccessToken,sendRefreshToken} = require('./token');

// Register a User

// Login a User

//Logout the user

//Setup a Protected mode


//Get a new accesstoken with a refresh token.
const server = express();

server.use(cookieparser());
server.use(
    cors({
        orgin:"http://localhost:8000",
        credentials:true
    })
);
server.use(express.json());
server.use(express.urlencoded({extended:true}));



server.post("/register", async function(req,res){
    const {email,password} = req.body;
    try{
        const user = fakeDb.find(function(e){
            return e.email === email
        });

        if(user){
            throw new Error("User already Exists");
        } 
        const hashPassword = await hash(password,10);
        //
        fakeDb.push({id:fakeDb.length,email,password:hashPassword});
        console.log(fakeDb);
        res.send({message:"Registered successfully"});
    }catch (err){
        res.send({message:err.message});
    }
});

// Login a User


server.post("/login", async function(req,res){
    const {email,password} = req.body;
    try{
        const user = fakeDb.find(function(e){
            return e.email === email
        });

        if(!user){
            throw new Error("User doesn't exists");
        } 

        const valid = await compare(password,user.password);
        if(!valid){
            throw new Error("Password not correct");
        } 
        // create Refresh access token
        const accesstoken = createAccessToken(user.id);
        const refreshtoken = createRefreshToken(user.id);

        // put the refresh token in database
        user.refreshtoken = refreshtoken;
        sendRefreshToken(res,refreshtoken);
        sendAccessToken(req,res,accesstoken);
        console.log(fakeDb);
    }catch (err){
        res.send({message:err.message});
    }
});

server.post("/logout", async function(req,res){

    res.clearCookie('refreshtoken',{path:'/refresh_token'});
    return res.send({
        message:'logout'
    });
});

server.post("/protected", async (req,res) => {
    try {
        const userid = isAuth(req);
        if(userid !== null){
            res.send({
                data:'secrect info'
            })
        }
    }catch(error){
        res.send(
            error.message
        )
    }
});

server.post("/refresh_token", function(req,res){
     const token = req.cookies.refreshtoken;
     console.log(token);
    if(!token) return res.send({accesstoken:''});
    let payload = null;
    try {
        payload = verify(token,process.env.REFRESH_TOKEN_SECRET);
    } catch (err){
        res.send({accesstoken:''});
    }
    console.log(payload);
    const user = fakeDb.find(user => user.id === payload.userId);
    console.log(user);
    if(!user) return res.send({accesstoken:''});
    if(user.refreshtoken != token){
       return res.send({accesstoken:''});
    }

    const accesstoken = createAccessToken(user.id);
    const refreshtoken = createRefreshToken(user.id);
    user.refreshtoken = refreshtoken;

    sendRefreshToken(res,refreshtoken);
    return res.send({accesstoken,refreshtoken});

});


server.listen(process.env.PORT,function(){
    console.log(`Server listening to port ${process.env.PORT}`);
});