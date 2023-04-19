const mongoose=require('mongoose')
const NoteSchema=new mongoose.Schema({
    heading:{
        type:String,
        required:[true,'please provide a heading'],
        trim:true
    },
    content:{
        type:String,
        required:[true,'please provide content'],
        trim:true
    },
    createdBy:{
        type:mongoose.Types.ObjectId,
        ref:'User',
        required:[true,'Please provide a user']
    },
    image:{
        type:String,
        default:'/uploads/zlatan.jpg'
    }
},{timestamps:true})
module.exports=mongoose.model('Note',NoteSchema)