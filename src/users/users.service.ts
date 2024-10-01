import {
  Injectable,
  ConflictException,
  BadRequestException,
  NotFoundException,
} from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { FilterQuery, Model, UpdateQuery } from 'mongoose';
import { hash } from 'bcryptjs';

import { User } from './schema/user.schema';
import { CreateUserRequest } from './dto/create-user.request';

@Injectable()
export class UsersService {
  constructor(
    @InjectModel(User.name) private readonly userModel: Model<User>,
  ) {}

  async create(data: CreateUserRequest) {
    try {
      const newUser = new this.userModel({
        ...data,
        password: await hash(data.password, 10),
      });
      await newUser.save();
    } catch (error) {
      if (error.code === 11000) {
        throw new ConflictException('User with this email already exists');
      }
      throw new BadRequestException('Error occurred while creating user');
    }
  }

  async getUser(query: FilterQuery<User>) {
    const user = await this.userModel.findOne(query);

    if (!user) {
      throw new NotFoundException('User not found.');
    }

    return user.toObject();
  }

  async getUsers() {
    return this.userModel.find({});
  }

  async updateUser(query: FilterQuery<User>, data: UpdateQuery<User>) {
    return this.userModel.findOneAndUpdate(query, data);
  }
}
