const mongoose= require('mongoose')
const bcrypt= require('bcryptjs')
const jwt= require('jsonwebtoken')
require('dotenv').config()
const validator= require('validator')
const UserSchema= new mongoose.Schema({
    email:{
        type:String,
        required:[true,'please provide email'],
        validate:{
            validator:validator.isEmail,
            message:'Please provide valid email'
        }
    },
    password:{
        type:String,
        required:[true,'please provide password'],
        minLength:6
    },
   /* role:{
        type:String,
        enum:['admin','user'],
        default:'user'
    },
    verificationToken:{
        type:String
    },
    isVerified:{
        type:Boolean,
        default:false
    },
    
    verified:Date,*/
    passwordToken:{
        type:String,
        default:null
    },
    passwordTokenExpirationDate:{
        type:Date,
        default:null
    },
    forgotPasswordEnabler:{
        type:Boolean,
        default:false
    }
},{timestamps:true,toJSON:{virtuals:true},toObject:{virtuals:true}})

/*UserSchema.statics.hashPassword=async function(){
    const salt = await bcrypt.genSalt(10)
    this.password=await bcrypt.hash(this.password,salt)
}*/
UserSchema.pre('save',async function(next){
    if(!this.isModified('password')) return
   const salt = await bcrypt.genSalt(10)
    this.password=await bcrypt.hash(this.password,salt)
    //await this.constructor.hashPassword()
   next()
})
/*UserSchema.pre('remove',async function(next){
    await this.model('Note').deleteMany({createdBy:this._id})
    next()
})*/
UserSchema.methods.createJWT=function(){
    return jwt.sign({
        userId:this._id,email:this.email},
        process.env.JWT_SECRET,{
        expiresIn:process.env.JWT_LIFETIME
    })
}
UserSchema.methods.comparePassword=async function(candidatePassword){
    const isMatch=await bcrypt.compare(candidatePassword,this.password)
    return isMatch
}
UserSchema.virtual('notes',{
    ref:'Note',
    localField:'_id',
    foreignField:'createdBy',
    justOne:false,
    match:{createdBy:this._id}
})
module.exports=  mongoose.model('User',UserSchema)