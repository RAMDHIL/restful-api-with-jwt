import  Express, { NextFunction, Response, Request } from "express"; 
import { PrismaClient } from "@prisma/client";
import { faker } from "@faker-js/faker";
import Bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import validator  from "validator";
import { accesValidation } from "../middleware/jwt";
const app = Express();
const prisma = new PrismaClient();


app.use(Express.json());
app.use((req,res,next) => {
    console.log(req.path);
    console.log(req.method);
    next();
})

//register user
app.use('/user-register',async (req,res) => {
    const{ email,password} = req.body
    if(validator.isEmail(email) && validator.isLength(password,{ min:8, max:20})){
        const hashedPassword = await Bcrypt.hash(password,10);
        const result = await prisma.data.create({
            data:{
                nama: faker.name.fullName(),
                umur: faker.number.int({max:50}).toString(),
                alamat: faker.address.street(),
                email,
                password:hashedPassword, 
            },
        });
        res.json({
            message:"user succes register"
        })
    }else{
        res.json({
            message:"terjadi kesalahan pada format password / email"
        })
    }
});

//login user
app.use('/user-login', async (req: any,res: any) => {
    const {email,password } = req.body
    try {
        const user = await prisma.data.findUnique({
            where: {
                email:email
            }
        });
        if(!user) {
            return res.status(500).json({ message:"email invalid"})
        }
        if(!user.password) { 
            return res.status(404).json({ message: "password not set"})
        }
        const isValidPassword = await Bcrypt.compare(password,user.password)
        const secret = process.env.JWT_SECRET!
        const payload = {
                    id:user.id,
                    nama:user.nama
                 } 
        const expiresIn = 60 * 60 * 1

        const token = jwt.sign(payload,secret, { expiresIn:expiresIn});
        if(isValidPassword) {
            return res.status(200).json({ 
                message:"succes login",
                data: {
                    id:user.id,
                    nama:user.nama
                },
                token:token    
            });
        }else{
            return res.status(403).json({
                message:"password wrong"
            })
        }
    } catch (error) {
        res.status(500).json({
            message:"server internal err"
        });   
    }
})
    
// read users
app.get('/get-user' ,accesValidation,async (req,res)=> {
    const result = await prisma.data.findMany()
    res.json({
        message:"succes get user",
        data: result
    });
});

//created user
app.post('/create-user', accesValidation,async (req,res)=> {
    // const { nama, umur, alamat} = req.body
    const result = await prisma.data.create({
        data:{
            nama: faker.name.fullName({ sex:"female"}),
            umur: faker.number.int({ min:10, max:70}).toString(),
            alamat: faker.address.country(),
        }
    })
    res.json({
        message: "succes create user",
        data:result        
    });
});

//edit user
app.patch('/edit-user/:id',accesValidation,async (req,res) => {
    const id  = req.params.id;
    try {
        const result = await prisma.data.update({
            where: {
              id: parseInt(id)  
            },
            data: {
                nama:faker.name.fullName(),
                umur:faker.number.int({min:10, max:70}).toString(),
                alamat:faker.location.city()
            }
        }) 
        res.json({
            message:`succes edit ${id} user`,
            data: result
        });
    } catch (error) {
        res.status(500).json({
            message:"failed updated"
        })
    }
  
});

//deleted user
app.delete('/delete-user/:id', accesValidation,async (req,res) => {
    const id = req.params.id
    try {
        const result = await prisma.data.delete({
            where: { 
                id:parseInt(id)
            }
        });
        res.status(200).json({
            message: "succes deleted user",
            data:result
        });
    } catch (error) {
        res.status(500).json({
            message:"failed deleted user",
        });
    }
});

//mencari route yang tidak ada
app.use((req,res) => {
    res.status(404).json({
        message: "not found"
    });
})

app.listen(3000,() => {
    console.log('server runing in port 3000');
}) 