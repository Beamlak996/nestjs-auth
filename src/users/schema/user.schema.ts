import { Schema, Prop, SchemaFactory } from "@nestjs/mongoose"
import { Types, SchemaTypes } from "mongoose"

@Schema()
export class User {
    @Prop({type: SchemaTypes.ObjectId, auto: true})
    _id: Types.ObjectId

    @Prop({unique: true})
    email: string

    @Prop()
    password: string
}

export const UserSchema = SchemaFactory.createForClass(User)

UserSchema.index({ email: 1 }, { unique: true });