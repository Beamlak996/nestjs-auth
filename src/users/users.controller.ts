import { Controller, Post, Get, Body, UseGuards } from '@nestjs/common';

import { CreateUserRequest } from './dto/create-user.request';
import { UsersService } from './users.service';
import { JwtAuthGuard } from 'src/auth/guards/jwt-auth.guard';
import { CurrentUser } from 'src/auth/current-user.decorator';
import { User } from './schema/user.schema';

@Controller('users')
export class UsersController {
    constructor(private readonly userService: UsersService) {}

    @Post()
    async createUser(@Body() request: CreateUserRequest) {
        await this.userService.create(request)
    }

    @Get()
    @UseGuards(JwtAuthGuard)
    async getUsers() {
        return this.userService.getUsers()
    }
}
