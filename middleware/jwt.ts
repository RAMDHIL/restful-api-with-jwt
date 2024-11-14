import { Request, Response,NextFunction } from "express";
import jwt from "jsonwebtoken";

interface UserData {
    id: string;
    nama: string;
}

interface ValidationRequest extends Request {
    userData: UserData
}

// middleware implementasi jwt
export const accesValidation = (req: Request,res:Response,next: NextFunction):any => {
    const ValidationReq = req as ValidationRequest;
    const {authorization} = ValidationReq.headers;

    if(!authorization){
        return res.status(401).json({
            message: "token tidak ditemukan"
        })
    }
    const secret = process.env.JWT_SECRET!;
    const token = authorization.split(' ')[1];

    try {
        const jwtDecode = jwt.verify(token,secret);
        if(typeof jwtDecode !== 'string'){
            ValidationReq.userData = jwtDecode as UserData
        }
    } catch (error) {
        return res.status(401).json({
            message:"unauthorized"
        })   
    }
    next();

}