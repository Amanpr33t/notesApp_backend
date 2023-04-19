const CustomAPIError = require('../errors/custom-error')
const {attachCookiesToResponse}=require('../utils/jwt')
const crypto= require('crypto')
const Token= require('../models/Token')
const {StatusCodes}=require('http-status-codes')

const refreshTokenCreator=async(req,res,user)=>{
    
    try {    
        const existingToken= await Token.findOne({user:user.userId})
    if(existingToken!==null && existingToken.isValid){
        const tokenValidity=existingToken.createdAt.getTime() + 1000*60*60*24
        if(tokenValidity<=Date.now()){
            await Token.findOneAndDelete({user:user._id})
        }else{
            const refreshToken=existingToken.refreshToken
            await attachCookiesToResponse({req,res,user,refreshToken})
            return
        }
    }
    const refreshToken= crypto.randomBytes(40).toString('hex')
    const userAgent= req.headers['user-agent']
    const ip= req.ip
    const isValid=true
    const userToken={
        refreshToken,
        ip,
        userAgent,
        user:user.userId,
        isValid
    }
    await Token.create(userToken)
    await attachCookiesToResponse({req,res,user,refreshToken})
    } catch (error) {
        console.log(error)
    }  
}
module.exports= refreshTokenCreator