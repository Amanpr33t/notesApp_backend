const jwt= require('jsonwebtoken')
require('dotenv').config()
const {StatusCodes}=require('http-status-codes')

const createJWT=({payload})=>{
    const token= jwt.sign(
        payload,
        process.env.JWT_SECRET,{
        expiresIn:process.env.JWT_LIFETIME
    })
    return token
}

const isTokenValid=(token)=>{
  return  jwt.verify(token,process.env.JWT_SECRET)
}

/*const attachCookiesToResponse=({res,token})=>{
    const oneDay= 1000*60*60*24
    res.cookie('token',token,{
        httpOnly:true,
        signed:true,
        expires:new Date(Date.now() + oneDay),
        secure:process.env.NODE_ENV==='production'
    })
}*/

const attachCookiesToResponse=async({req,res,user,refreshToken})=>{
    try {
        const accessTokenJWT= createJWT({payload:{user}})
    const refreshTokenJWT=createJWT({payload:{user,refreshToken}})
    const oneDay= 1000*60*60*24
    await res.cookie('accessToken',accessTokenJWT,{
        httpOnly:true,
        signed:true,
        expires:new Date(Date.now() + 1000*60*60),
        secure:process.env.NODE_ENV==='production'
    }).cookie('refreshToken',refreshTokenJWT,{
        httpOnly:true,
        signed:true,
        expires:new Date(Date.now()+oneDay),
        secure:process.env.NODE_ENV==='production'
    }).status(StatusCodes.OK).json({status:'ok',isVerified:true})
    } catch (error) {
        console.log(error)
    }
    }

module.exports={
    createJWT,isTokenValid,attachCookiesToResponse
}