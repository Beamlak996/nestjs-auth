import { Injectable, ConflictException } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { hash } from 'bcryptjs';

import { User } from './schema/user.schema';
import { CreateUserRequest } from './dto/create-user.request';

@Injectable()
export class UsersService {
  constructor(
    @InjectModel(User.name) private readonly userModal: Model<User>,
  ) {}

  async create(data: CreateUserRequest) {
    try {
      const newUser = new this.userModal({
        ...data,
        password: await hash(data.password, 10),
      });
      await newUser.save();
    } catch (error) {
      if (error.code === 11000) {
        throw new ConflictException('User with this email already exists');
      }
      throw error;
    }
  }
}
