using JWTAPI.Model;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;


namespace JWTAPI.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        public static User user = new User();
        private readonly IConfiguration _configuration;
        
       public AuthController(IConfiguration configuration) {
            _configuration = configuration;
        
       }



        /// <summary>
        /// Register User
        /// </summary>
        /// <param name="requestDto"></param>
        /// <returns></returns>
       [HttpPost("register")]
       public ActionResult<User> Register(UserDto requestDto)
        {
            string PasswordHash = BCrypt.Net.BCrypt.HashPassword(requestDto.Password);
            user.UserName = requestDto.UserName;
            user.PasswordHash = PasswordHash;

            return Ok(user);
        }


        /// <summary>
        /// Accessing using JWT Token
        /// </summary>
        /// <param name="requestDto"></param>
        /// <returns></returns>
        [HttpPost("login")]
        public ActionResult<User> Login(UserDto requestDto)
        {
            if (user.UserName != requestDto.UserName)
            {
                return BadRequest("User not found");
            }

            if (!BCrypt.Net.BCrypt.Verify(requestDto.Password,user.PasswordHash))
            {
                return BadRequest("Worng Password!");

            }


            string token = CreateToken(user);

            return Ok(token);
        }


        /// <summary>
        /// Generate Token for JWT
        /// </summary>
        /// <param name="user"></param>
        /// <returns></returns>
        private string CreateToken(User user)
        {
            List<Claim> claims = new List<Claim>
            {
                new Claim(ClaimTypes.Name, user.UserName)
            };

            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(
                _configuration.GetSection("AppSetting:JWToken").Value!));

            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

            var token = new JwtSecurityToken(
                claims: claims,
                expires: DateTime.UtcNow.AddHours(1),
                signingCredentials: creds
            );

            var jwt = new JwtSecurityTokenHandler().WriteToken(token);

            return jwt;

        }
    }
}
