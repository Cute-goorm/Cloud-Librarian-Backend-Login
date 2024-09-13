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

    // provider : social login 종류 (google / kakao)
    private String provider;

    // providerId : social login 유저의 고유 ID
    private String providerId;
}
