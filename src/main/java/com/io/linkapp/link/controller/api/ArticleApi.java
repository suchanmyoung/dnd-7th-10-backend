package com.io.linkapp.link.controller.api;

import com.io.linkapp.config.security.auth.PrincipalDetails;
import com.io.linkapp.link.controller.predicate.ArticleFormPredicate;
import com.io.linkapp.link.request.ArticleRequest;
import com.io.linkapp.link.request.ArticleTagRequest;
import com.io.linkapp.link.response.ArticleResponse;
import com.io.linkapp.link.response.SuccessResponse;
import com.io.linkapp.link.service.ArticleService;
import com.io.linkapp.user.domain.User;
import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import java.util.List;
import java.util.UUID;
import javax.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@Api(value = "Article", tags = {"Article"})
@RequiredArgsConstructor
@RestController
public class ArticleApi {

    private final ArticleService articleService;

    @ApiOperation("링크 저장")
    @PostMapping("/article")
    public ArticleResponse add(@RequestBody @Valid ArticleRequest articleRequest, @AuthenticationPrincipal PrincipalDetails principalDetails) {
        return articleService.add(articleRequest, principalDetails.getUser());
    }

    @ApiOperation("링크 전체 조회")
    @GetMapping("/articles")
    public List<ArticleResponse.Tags> getList(@AuthenticationPrincipal PrincipalDetails principalDetails) {
        return articleService.getList(principalDetails.getUser());
    }

    @ApiOperation("링크 Description 검색")
    @GetMapping("/articles/description/{description}")
    public List<ArticleResponse.Tags> searchArticleByDescription(@PathVariable String description, @AuthenticationPrincipal PrincipalDetails principalDetails) {
        User user = principalDetails.getUser();
        ArticleRequest.OpenGraphSearch searchCondition = ArticleRequest.OpenGraphSearch.builder()
                .user(user)
                .openGraphTag(description)
                .build();

       return articleService.getListByDescription(ArticleFormPredicate.descriptionSearch(searchCondition));
    }

    @ApiOperation("링크 Title 검색")
    @GetMapping("/articles/title/{linkTitle}")
    public List<ArticleResponse.Tags> searchArticleByLinkTitle(@PathVariable String linkTitle, @AuthenticationPrincipal PrincipalDetails principalDetails) {
        User user = principalDetails.getUser();
        ArticleRequest.OpenGraphSearch searchCondition = ArticleRequest.OpenGraphSearch.builder()
                .user(user)
                .openGraphTag(linkTitle)
                .build();

        return articleService.getListByDescription(ArticleFormPredicate.titleSearch(searchCondition));
    }

    @ApiOperation("링크 조회")
    @GetMapping("/article/{articleId}")
    public ArticleResponse.Tags get(@PathVariable("articleId") UUID uuid) {
        return articleService.findById(uuid);
    }

    @ApiOperation("링크 삭제")
    @DeleteMapping("/article/{articleId}")
    public SuccessResponse remove(@PathVariable("articleId") UUID uuid) {
        return articleService.remove(uuid);
    }

    @ApiOperation(value = "북마크 등록/해제", notes = "등록 상태에서 요청 시 해제, 해제 상태에서 요청 시 등록")
    @PatchMapping("/article/mark/{articleId}")
    public ArticleResponse bookmark(@PathVariable("articleId") UUID uuid,@AuthenticationPrincipal PrincipalDetails principalDetails){
        System.out.println(principalDetails.getUser().getId()); //현재 유저 아이디 알 수 있음
        UUID userId = principalDetails.getUser().getId();
        return articleService.bookmark(uuid,userId);
    }

    @ApiOperation(value = "아티클에 태그 등록")
    @PostMapping("/article/tag")
    public SuccessResponse tag(@RequestBody ArticleTagRequest articleTag) {
        return articleService.setTagInArticle(articleTag);
    }
}
