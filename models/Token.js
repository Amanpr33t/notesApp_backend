const mongoose= require('mongoose')
const TokenSchema= new mongoose.Schema({
    refreshToken:{
        type:String
    },
    ip:{
        type:String
    },
    userAgent:{
        type:String
    },
    isValid:{
        type:Boolean 
    },
    user:{
        type:mongoose.Types.ObjectId,
        ref:'User'
    }
},{timestamps:true})
module.exports=mongoose.model('Token',TokenSchema)