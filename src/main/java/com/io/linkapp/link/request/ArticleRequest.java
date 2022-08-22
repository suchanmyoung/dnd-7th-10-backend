package com.io.linkapp.link.request;

import com.io.linkapp.user.domain.User;
import lombok.Builder;
import lombok.Getter;

import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

@Getter
public class ArticleRequest {

    private UUID folderId;
    private String linkUrl;
    private List<UUID> tagIds = new ArrayList<>();

    @Builder
    public ArticleRequest(UUID folderId, String linkUrl, List<UUID> tagIds) {
        this.folderId = folderId;
        this.linkUrl = linkUrl;
        this.tagIds = tagIds;
    }

    @Getter
    @Builder
    public static class OpenGraphSearch {
        private User user;
        //오픈그래프 정보 중 Title, Description 을 받을 수 있는 문자열
        private String openGraphTag;
    }
}
