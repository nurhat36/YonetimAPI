using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Yonetim.Shared.Models; // Modeller buradaysa
using Yonetim.Shared.Data;   // DbContext buradaysa

namespace YonetimAPI.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class BuildingsController : ControllerBase
    {
        private readonly ApplicationDbContext _context;

        public BuildingsController(ApplicationDbContext context)
        {
            _context = context;
        }

        [HttpGet]
        public async Task<ActionResult<IEnumerable<Building>>> GetBuildings()
        {
            return await _context.Buildings.ToListAsync();
        }
    }
}
