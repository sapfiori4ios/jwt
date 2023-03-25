const {verify} = require('jsonwebtoken');

const isAuth = function(req) {
    const authorization = req.header('authorization');
   
    if(!authorization) throw new Error('You need to login');
    const token = authorization.split(' ')[1];
    console.log(authorization);
    const { userId } = verify(token,process.env.ACCESS_TOKEN_SECRET);
    console.log(userId)
    return userId;
}

module.exports = {
    isAuth,
}
