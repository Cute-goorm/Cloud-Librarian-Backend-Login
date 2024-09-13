package com.groom.cloudlibrarian.login.dto;

import com.groom.cloudlibrarian.login.MemberRole;
import jakarta.persistence.*;
import lombok.*;

@Entity
@Builder
@Getter @Setter
@NoArgsConstructor
@AllArgsConstructor
public class Member {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name="member_id")
    private Long id;

    private String loginId;
    private String password;
    private String nickname;
    private String image;

    @Enumerated(EnumType.STRING)
    private MemberRole role;

    // provider : google이 들어감
    private String provider;

    // providerId : 구글 로그인 한 유저의 고유 ID가 들어감
    private String providerId;
}
