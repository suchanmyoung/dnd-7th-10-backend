package com.io.linkapp.user.mapper;

import com.io.linkapp.user.domain.User;
import com.io.linkapp.user.request.UserRequest;
import org.mapstruct.Mapper;
import org.mapstruct.factory.Mappers;

@Mapper
public interface UserMapper {
    UserMapper INSTANCE = Mappers.getMapper(UserMapper.class);

    User toEntity(UserRequest userRequest);
}
