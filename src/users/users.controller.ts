import { Controller, Post, Body } from '@nestjs/common';

import { CreateUserRequest } from './dto/create-user.request';
import { UsersService } from './users.service';

@Controller('users')
export class UsersController {
    constructor(private readonly userService: UsersService) {}

    @Post()
    async createUser(@Body() request: CreateUserRequest) {
        await this.userService.create(request)
    }
}
