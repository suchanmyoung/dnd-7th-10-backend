package com.io.linkapp.user.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.io.linkapp.config.security.jwt.JwtProperty;
import com.io.linkapp.config.security.jwt.JwtResponse;
import com.io.linkapp.config.security.jwt.JwtTokenProvider;
import com.io.linkapp.exception.ErrorResponse;
import com.io.linkapp.exception.RefreshTokenNotFoundException;
import com.io.linkapp.exception.RefreshTokenNotValidateException;
import com.io.linkapp.link.request.KakaoRequest;
import com.io.linkapp.user.domain.User;
import com.io.linkapp.user.request.UserRequest;
import com.io.linkapp.user.response.UserResponse;
import com.io.linkapp.user.service.RedisService;
import com.io.linkapp.user.service.UserService;
import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.web.bind.annotation.*;

import javax.validation.Valid;
import java.util.List;

@Slf4j
@Api(value = "User", tags = {"User"})
@RequiredArgsConstructor
@RestController
public class UserApi {

    private final UserService userService;
    private final RedisService redisService;

    @ApiOperation("회원 가입")
    @PostMapping("/user")
    public User join(@RequestBody @Valid UserRequest userRequest) {
        return userService.join(userRequest);
    }

    @ApiOperation("회원 찾기")
    @GetMapping("/user/{username}")
    public UserResponse getUser(@PathVariable("username") String username){
        return userService.findUser(username);
    }

    @ApiOperation("회원 전체 조회")
    @GetMapping("/users")
    public List<UserResponse> getUsers(){
        return userService.findAll();
    }

    @ApiOperation(value = "카카오 로그인", notes = "첫 요청 시 회원가입 후 로그인, 이후 요청은 로그인")
    @PostMapping("/kakao")
    public JwtResponse kakaoLogin(@RequestBody KakaoRequest kakaoRequest) {
        return userService.kakaoLogin(kakaoRequest);
    }

//    @ApiOperation(value = "액세스 토큰 재발급")
//    @GetMapping("/refresh")
//    public void reGenerateAccessToken(@RequestParam String refreshToken){
//        JwtTokenProvider jwtTokenProvider = new JwtTokenProvider(redisService);
//                try {
//
//                    String accessToken = jwtTokenProvider.findRefreshToken(refreshToken)
//                            .validateRefreshToken()
//                            .regenerateAccessToken();
//
//                    response.addHeader(JwtProperty.HEADER, JwtProperty.TOKEN_PREFIX + accessToken);
//
//                    JwtResponse responseAccessToken = JwtResponse.builder()
//                            .header(JwtProperty.HEADER)
//                            .accessToken(JwtProperty.TOKEN_PREFIX + accessToken)
//                            .build();
//
//                    ObjectMapper objectMapper = new ObjectMapper();
//                    response.getWriter().write(objectMapper.writeValueAsString(responseAccessToken));
//                    return;
//                } catch (RefreshTokenNotFoundException e) {
//                    log.error("RefreshToken Error!", e);
//                    ErrorResponse error = ErrorResponse.customBuilder()
//                            .error("RefreshTokenNotFoundException")
//                            .status(404)
//                            .message("Can not Found Refresh Token.")
//                            .build();
//                    ObjectMapper objectMapper = new ObjectMapper();
//                    response.getWriter().write(objectMapper.writeValueAsString(error));
//                    return;
//                } catch (RefreshTokenNotValidateException e){
//                    log.error("RefreshToken Error!", e);
//                    ErrorResponse error = ErrorResponse.customBuilder()
//                            .error("RefreshTokenNotValidatedException")
//                            .status(400)
//                            .message("Refresh Token is Not Validated.")
//                            .build();
//                    ObjectMapper objectMapper = new ObjectMapper();
//                    response.getWriter().write(objectMapper.writeValueAsString(error));
//                    return;
//                }
//        }
}
