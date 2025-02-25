package com.io.linkapp.link.controller.mapper;

import com.io.linkapp.link.domain.Article;
import com.io.linkapp.link.domain.Remind;
import com.io.linkapp.link.request.RemindRequest.Add;
import com.io.linkapp.link.response.RemindResponse.GetAll;
import java.util.ArrayList;
import java.util.List;
import javax.annotation.processing.Generated;
import org.springframework.stereotype.Component;

@Generated(
    value = "org.mapstruct.ap.MappingProcessor",
    date = "2022-09-30T23:38:49+0900",
    comments = "version: 1.4.2.Final, compiler: javac, environment: Java 17.0.2 (Oracle Corporation)"
)
@Component
public class RemindFormMapperImpl extends RemindFormMapper {

    @Override
    public Remind toRemind(Add in) {
        if ( in == null ) {
            return null;
        }

        Remind remind = new Remind();

        remind.setRemindTitle( in.getRemindTitle() );
        remind.setUserId( in.getUserId() );

        return remind;
    }

    @Override
    public GetAll toGetAll(Remind in) {
        if ( in == null ) {
            return null;
        }

        GetAll getAll = new GetAll();

        getAll.setRemindId( in.getRemindId() );
        getAll.setUserId( in.getUserId() );
        getAll.setCron( in.getCron() );
        getAll.setRemindTitle( in.getRemindTitle() );
        List<Article> list = in.getArticleList();
        if ( list != null ) {
            getAll.setArticleList( new ArrayList<Article>( list ) );
        }

        return getAll;
    }

    @Override
    public List<GetAll> toGetAllList(List<Remind> in) {
        if ( in == null ) {
            return null;
        }

        List<GetAll> list = new ArrayList<GetAll>( in.size() );
        for ( Remind remind : in ) {
            list.add( toGetAll( remind ) );
        }

        return list;
    }
}
