import { IsEmail, IsStrongPassword, IsString } from "class-validator"

export class CreateUserRequest {
    @IsEmail()
    email: string

    @IsString()
    // @IsStrongPassword()
    password: string
}