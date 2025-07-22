using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using System;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using Yonetim.Shared.Models;
using YonetimAPI.ViewModels;
using YonetimAPI.Helpers;
using Microsoft.AspNetCore.Authorization;

namespace YonetimAPI.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class AuthController : ControllerBase
    {
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly IConfiguration _configuration;
        private readonly IWebHostEnvironment _env;
        private readonly ILogger<AuthController> _logger;

        public AuthController(SignInManager<ApplicationUser> signInManager, UserManager<ApplicationUser> userManager, IConfiguration configuration, IWebHostEnvironment env, ILogger<AuthController> logger)
        {
            _signInManager = signInManager;
            _userManager = userManager;
            _configuration = configuration;
            _env = env;
            _logger = logger;
        }
        [HttpPost("register")]
        [Consumes("multipart/form-data")]
        public async Task<IActionResult> Register([FromForm] RegisterRequest model)
        {
            if (string.IsNullOrWhiteSpace(model.UserName) ||
                string.IsNullOrWhiteSpace(model.Email) ||
                string.IsNullOrWhiteSpace(model.Password))
            {
                return BadRequest("Tüm alanlar zorunludur.");
            }

            var slug = SlugHelper.GenerateSlug(model.UserName);

            // slug varsa random ekle
            if (await _userManager.Users.AnyAsync(u => u.Slug == slug))
            {
                slug += "-" + Guid.NewGuid().ToString("N").Substring(0, 6);
            }

            string imagePath = null;

            if (model.ProfileImage != null && model.ProfileImage.Length > 0)
            {
                var uploadDir = Path.Combine(_env.WebRootPath ?? Path.Combine(Directory.GetCurrentDirectory(), "wwwroot"), "userimages");
                if (!Directory.Exists(uploadDir)) Directory.CreateDirectory(uploadDir);

                var uniqueFileName = Guid.NewGuid().ToString() + Path.GetExtension(model.ProfileImage.FileName);
                var filePath = Path.Combine(uploadDir, uniqueFileName);

                using (var stream = new FileStream(filePath, FileMode.Create))
                {
                    await model.ProfileImage.CopyToAsync(stream);
                }

                imagePath = "/userimages/" + uniqueFileName;
            }

            var user = new ApplicationUser
            {
                UserName = model.UserName,
                Email = model.Email,
                Slug = slug,
                ProfileImageUrl = imagePath
            };

            var result = await _userManager.CreateAsync(user, model.Password);

            if (result.Succeeded)
            {
                return Ok(new { Message = "Kayıt başarılı", user.UserName });
            }

            return BadRequest(result.Errors);
        }

        [HttpGet("me")]
        [Authorize]
        public async Task<IActionResult> GetProfile()
        {
            try
            {
                var allClaims = User?.Claims.ToList();
                _logger.LogInformation("Token Claims:");
                foreach (var c in allClaims)
                {
                    _logger.LogInformation($"Type: {c.Type} - Value: {c.Value}");
                }

                // Öncelikle en çok kullanılan claim türlerini sırayla dene
                var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
                // Bu genelde GUID ID olur
                if (string.IsNullOrEmpty(userId))
                {
                    userId = User.FindFirstValue("nameid"); // Alternatif olarak "nameid" claim'i
                }
                if (string.IsNullOrEmpty(userId))
                {
                    userId = User.FindFirstValue(JwtRegisteredClaimNames.NameId); // JWT standart claim'i
                }
                if (string.IsNullOrEmpty(userId))
                {
                    _logger.LogWarning("❗ UserId claim'i token içinde bulunamadı.");
                    return Unauthorized(new
                    {
                        message = "Kimlik doğrulama başarısız.",
                        detay = "UserId claim'i bulunamadı. Lütfen geçerli bir JWT token kullanın."
                    });
                }

                _logger.LogInformation($"✅ Kullanıcı ID'si çözümlendi: {userId}");

                // Kullanıcıyı veritabanından bul
                var user = await _userManager.FindByIdAsync(userId);
                if (user == null)
                {
                    _logger.LogWarning($"❗ Kullanıcı bulunamadı. ID: {userId}");
                    return NotFound(new
                    {
                        message = "Kullanıcı bulunamadı.",
                        detay = $"ID: {userId} olan kullanıcı sistemde kayıtlı değil."
                    });
                }

                // Profil bilgileri response'a
                var profile = new
                {
                    user.Id,
                    user.UserName,
                    user.Email,
                    user.PhoneNumber,
                    user.ProfileImageUrl
                };

                return Ok(profile);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "🚨 [GetProfile] sırasında beklenmeyen bir hata oluştu.");
                return StatusCode(500, new
                {
                    message = "Sunucu hatası meydana geldi.",
                    detay = ex.Message
                });
            }
        }






        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] LoginRequest request)
        {
            // Kullanıcı adı veya email ile kullanıcıyı bul
            var user = await _userManager.FindByNameAsync(request.Username); // veya FindByEmailAsync olabilir
            if (user == null)
                return Unauthorized("Kullanıcı bulunamadı.");

            // Parola doğrulaması yap
            var result = await _signInManager.CheckPasswordSignInAsync(user, request.Password, false);
            if (!result.Succeeded)
                return Unauthorized("Şifre yanlış.");

            // Token üret
            var token = GenerateJwtToken(user);

            return Ok(new { token });
        }

        private string GenerateJwtToken(ApplicationUser user)
        {
            var claims = new[]
            {
        new Claim(JwtRegisteredClaimNames.Sub, user.Id),           // Kullanıcı adı
        new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
        new Claim(ClaimTypes.NameIdentifier, user.Id),                   // Sadece kullanıcı ID'si burada
        new Claim(ClaimTypes.Name, user.UserName),                       // Kullanıcı adı (farklı claim tipi)
        new Claim(ClaimTypes.Email, user.Email)
    };

            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["Jwt:Key"]));
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
            var expires = DateTime.Now.AddMinutes(Convert.ToDouble(_configuration["Jwt:ExpireMinutes"]));

            var token = new JwtSecurityToken(
                issuer: _configuration["Jwt:Issuer"],
                audience: _configuration["Jwt:Audience"],
                claims: claims,
                expires: expires,
                signingCredentials: creds
            );

            return new JwtSecurityTokenHandler().WriteToken(token);
        }


        [HttpPost("logout")]
        [Authorize]
        public async Task<IActionResult> Logout()
        {
            try
            {
                await _signInManager.SignOutAsync(); // Identity çıkışı (Cookie tabanlı senaryolarda anlamlıdır)

                // İstemci tarafı token'ı sileceği için ek olarak bir işlem yapmana gerek yok.
                _logger.LogInformation($"🟢 Kullanıcı çıkış yaptı: {User.Identity?.Name}");

                return Ok(new { message = "Çıkış başarılı. Lütfen token'ı istemciden silin." });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "🚨 Logout sırasında bir hata oluştu.");
                return StatusCode(500, new { message = "Çıkış işlemi sırasında bir hata oluştu.", detay = ex.Message });
            }
        }


    }

    public class LoginRequest
    {
        public string Username { get; set; }
        public string Password { get; set; }
    }
}
