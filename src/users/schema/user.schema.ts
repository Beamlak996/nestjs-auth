import { Schema, Prop, SchemaFactory } from '@nestjs/mongoose';
import { Types, SchemaTypes } from 'mongoose';

@Schema()
export class User {
  @Prop({ type: SchemaTypes.ObjectId, auto: true })
  _id: Types.ObjectId;

  @Prop({ unique: true })
  email: string;

  @Prop()
  password: string;

  @Prop()
  refreshToken?: string;
}

export const UserSchema = SchemaFactory.createForClass(User);

UserSchema.set('toJSON', {
  transform: (doc, ret) => {
    ret.id = ret._id;
    delete ret._id;

    delete ret.password;
    delete ret.refreshToken;
    delete ret.__v; 
  },
});

UserSchema.index({ email: 1 }, { unique: true });
