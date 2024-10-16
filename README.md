# oauth2-jwt-boilerplate
OAuth2 + JWT 재사용가능 로그인 코드

사용 기술
1. 토큰 총 3군데 관리
   - client
     - localstorage: 엑세스 토큰
     - cookie: 리프레시 토큰   
   - server:
     - Redis: 리프레시 토큰
       
2. Refresh 토큰 블랙리스팅(서버 저장소에서 리프레시 토큰 삭제) 
3. 로그아웃(쿠키에 있는 토큰 삭제)
4. Redis 스케줄러러 토큰 자동 expire
5. 로그인 될 때, 프론트 재 요청을 통해서 토큰 local storage로 주기
