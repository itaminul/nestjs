
auth - service.ts
-----------------
    I                                                                                                                                                                                                                m                                                                                                                                                                     por                                                                                                                                                                               t { BadRequestException, ForbiddenException, HttpStatus, Injectable } from "@nestjs/comm on";
// import * as argon from 'argon2'
import { PrismaService } from "src/prisma/prisma.service";
import { AuthDto } from "./dto/auth.dto";
import { JwtService } from "@nestjs/jwt";
import { ConfigService } from "@nestjs/config";
import * as bcrypt from 'bcrypt'
@Injectable()
export class AuthService {
    constructor(
        private prisma: PrismaService,
        private jwtService: JwtService,
        private configService: ConfigService
    ) { }
    async getAll() {
        return this.prisma.user.findMany({
            orderBy: {
                id: 'desc'
            }
        })
    }
    async register(authDto: AuthDto) {
        try {
            // const hashPasswor = await argon.hash(authDto.hashPassword);
            const saltOrRounds = 10;
            const pass = authDto.hashPassword;
            const hash = await bcrypt.hash(pass, saltOrRounds);
            // const haspa = await
            const user = this.prisma.user.create({
                data: {
                    userName: authDto.userName,
                    hashPassword: hash,
                    // orgId: authDto.orgId,
                    // roleId: authDto.roleId
                },
                select: {
                    userName: true,
                    hashPassword: true
                    // email: true,
                    // orgId: true
                }
            })
            return user;
        } catch (error) {
            if (error.code == 'P2002') {
                throw new ForbiddenException('User already exist')
            }
        }
    }
    async login(authDto: AuthDto) {
        //find user with input user name
        const user = await this.prisma.user.findUnique({
            where: {
                userName: authDto.userName
            }
        })
        // console.log("user", user)
        //check user exist
        if (!user) {
            throw new ForbiddenException(
                'User not found'
            )
        }
        //check password matched
        const passwordMached = await bcrypt.compare(authDto.hashPassword, user.hashPassword)
        // const passwordMached = await argon.verify(
        // user.hashPassword,
        // authDto.hashPassword
        // )
        if (!passwordMached) {
            throw new ForbiddenException(
                'Incorrect password'
            )
        }
        delete user.hashPassword;
        return await this.signJwtString(user.id, user.userName, user.email, user.orgId);
    }
    async signJwtString(userId: number, userName: string, email: string, orgId: number): Promise<any> {
        const payload = {
            sub: userId,
            userName,
            email,
            orgId
        }
        const jwtString = await this.jwtService.signAsync(payload, {
            expiresIn: '1d',
            secret: this.configService.get('JWT_SECRET')
        })
        // console.log("payload", payload)
        return {
            accessToken: jwtString,
        }
    }
    async validateUser(userName, hashPassword): Promise<any> {
        // console.log('vvv');
        const user = await this.prisma.user.findUnique({
            where: {
                userName: userName
            }
        });
        if (user && user.hashPassword === hashPassword) {
            const { hashPassword, ...result } = user;
            return result;
        }
        return null;
    }
}
------------------------------------------------------------------------------------
    auth - controller.ts
----------------------------------------------------------------------------------
    I                                       m                                                                                                                                                                 p                                                                                                ort { BadR                                                                           equestException, Body, Controller, Get, HttpStatus, Post, Req, Request, Session, UseGuards } from "@nestjs/common";
import { AuthService } from "./auth.service";
import { AuthDto } from "./dto/auth.dto";
import { AuthGuard } from "@nestjs/passport";
@Controller('auth')
export class AuthController {
    constructor(private authService: AuthService) { }
    @Get()
    async getAll() {
        try {
            const result = await this.authService.getAll()
            return { status: HttpStatus.OK, result }
        } catch (error) {
            throw new BadRequestException(error);
        }
    }
    @Post("register")
    register(@Body() authDto: AuthDto) {
        const { userName, hashPassword } = authDto;
        // console.log(userName, password);
        try {
            const result = this.authService.register(authDto);
            return { status: HttpStatus.OK, result }
        } catch (error) {
            throw new BadRequestException(error)
        }
    }
    // @UseGuards(AuthGuard('local'))
    @Post("login")
    login(
        @Body() authDto: AuthDto
    ) {
        return this.authService.login(authDto)
    }



    @Get('')
    async getAuthSession(@Session() session: Record<string, any>) {
        console.log(session);
        console.log(session.id);
        session.authenticated = true;
        return session;
    }
}
----------------------------------------
    jwt - strategy.ts
----------------------------------------
import { Injectable } from "@nestjs/common";
import { ConfigService } from "@nestjs/config";
import { PassportStrategy } from "@nestjs/passport";
import { ExtractJwt, Strategy } from "passport-jwt";
import { PrismaService } from "src/prisma/prisma.service";
@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy, 'jwt') {
    constructor(
        configService: ConfigService,
        public prisma: PrismaService
    ) {
        super({
            //token string is added to every request(except login/register)
            jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
            secretOrKey: configService.get('JWT_SECRET')
        })
    }
    async validate(payload: { sub: number; username: string }) {
        // console.log(JSON.stringify(payload));
        const user = await this.prisma.user.findUnique({
            where: {
                id: payload.sub
            }
        })
        delete user.hashPassword
        return user;
    }
}
------------------------------main.ts----------------------------------------
import { ValidationPipe } from '@nestjs/common';
import { HttpAdapterHost, NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import * as session from 'express-session';
import * as passport from 'passport';
import { SwaggerModule, DocumentBuilder } from '@nestjs/swagger';
import { PrismaClientExceptionFilter } from './prisma-client-exception.filter';
// import { PrismaService } from './prisma/prisma.service';
async function bootstrap() {
    const app = await NestFactory.create(AppModule);
    const config = new DocumentBuilder()
        .setTitle('SCMS API')
        .setDescription('The SCMS API description')
        .setVersion('1.0')
        .addTag('scms')
        .addBearerAuth()
        .build();
    const options = {
        customCss: '.swagger-ui .topbar { display: none }',
        customSiteTitle: "New Title",
        customfavIcon: "/assets/favicon.ico"
    };
    const document = SwaggerModule.createDocument(app, config);
    SwaggerModule.setup('ati-scms/api', app, document, {
        customSiteTitle: 'ATI SCMS API',
        //customfavIcon: '../favicon.jpg'
    });



    app.use(
        session({
            name: 'nestjs_custome_session_id',
            secret: 'my-secret',
            resave: false,
            saveUninitialized: true,
            // cookie: {
            // maxAge: 24 * 60 * 60 * 1000,
            // }
        })),
        // const prismaService = app.get(PrismaService);
        // await prismaService.enableShutdownHooks(app)
        app.useGlobalPipes(new ValidationPipe())
    app.use(passport.initialize())
    app.use(passport.session())
    const { httpAdapter } = app.get(HttpAdapterHost)
    app.useGlobalFilters(new PrismaClientExceptionFilter(httpAdapter))
    app.enableCors()
    await app.listen(9001);
}
bootstrap();
