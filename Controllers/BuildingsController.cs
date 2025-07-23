using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Yonetim.Shared.Data;
using Yonetim.Shared.Models;
using Yonetim.Shared.Models.ViewModels;
using Yonetim.Shared.Services.Interfaces;
using Yonetim.Shared.Services.Implementations;
using Yonetim.Shared.Security;
using Yonetim.Shared.Services;

namespace YonetimAPI.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    [Authorize]
    public class BuildingsController : ControllerBase
    {
        private readonly ApplicationDbContext _context;
        private readonly IBuildingService _buildingService;
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly IWebHostEnvironment _hostingEnvironment;

        public BuildingsController(ApplicationDbContext context,
            IBuildingService buildingService,
            UserManager<ApplicationUser> userManager,
            IWebHostEnvironment hostingEnvironment)
        {
            _context = context;
            _buildingService = buildingService;
            _userManager = userManager;
            _hostingEnvironment = hostingEnvironment;
        }

        [HttpGet("user-buildings")]
        public async Task<IActionResult> GetUserBuildings()
        {
            var currentUserId = _userManager.GetUserId(User);
            var userProfile = await _context.UserProfiles
                .FirstOrDefaultAsync(up => up.IdentityUserId == currentUserId);

            if (userProfile == null) return NotFound();

            var buildingsWithRoles = await _context.UserBuildingRoles
                .Where(ubr => ubr.UserProfileId == userProfile.Id)
                .Include(ubr => ubr.Building)
                .Select(ubr => new
                {
                    ubr.Building,
                    ubr.Role
                }).ToListAsync();

            return Ok(buildingsWithRoles);
        }

        [HttpGet("{buildingId}/details")]
        [Authorize(Policy = "BuildingAccess")]
        public async Task<IActionResult> GetDetails(int buildingId)
        {
            var building = await _buildingService.GetBuildingByIdAsync(buildingId);
            if (building == null) return NotFound();

            var currentUserId = _userManager.GetUserId(User);
            var userProfile = await _context.UserProfiles
                .FirstOrDefaultAsync(up => up.IdentityUserId == currentUserId);

            if (userProfile == null) return NotFound();

            var role = await _buildingService.GetUserRoleInBuildingAsync(userProfile.Id, building.Id);
            var managers = await _buildingService.GetBuildingManagersAsync(building.Id);

            return Ok(new { building, role, managers });
        }

        [HttpGet("{buildingId}/dashboard")]
        [Authorize(Policy = "BuildingAccess")]
        public async Task<IActionResult> GetDashboard(int buildingId)
        {
            var building = await _context.Buildings
                .Include(b => b.Incomes)
                .Include(b => b.Expenses)
                .Include(b => b.Units)
                .Include(b => b.Announcements)
                .Include(b => b.UserDebts)
                .FirstOrDefaultAsync(b => b.Id == buildingId);

            if (building == null) return NotFound();

            var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
            var currentUserDebt = await _context.UserDebts
                .Where(ud => ud.UserId == userId && ud.BuildingId == buildingId)
                .SumAsync(ud => ud.Amount);

            var lastPayment = await _context.Incomes
                .Where(i => i.BuildingId == buildingId && i.PayerId == userId)
                .OrderByDescending(i => i.Date)
                .FirstOrDefaultAsync();

            var sixMonthsAgo = DateTime.Now.AddMonths(-6);
            var lastSixMonths = Enumerable.Range(0, 6).Select(i => DateTime.Now.AddMonths(-i).ToString("MMM yyyy")).Reverse().ToList();

            var incomeByMonth = Enumerable.Range(0, 6)
                .Select(i => building.Incomes.Where(inc => inc.Date.Month == DateTime.Now.AddMonths(-i).Month && inc.Date.Year == DateTime.Now.AddMonths(-i).Year).Sum(inc => inc.Amount)).Reverse().ToList();

            var expenseByMonth = Enumerable.Range(0, 6)
                .Select(i => building.Expenses.Where(exp => exp.Date.Month == DateTime.Now.AddMonths(-i).Month && exp.Date.Year == DateTime.Now.AddMonths(-i).Year).Sum(exp => exp.Amount)).Reverse().ToList();

            var totalUnits = building.Units.Count;
            var paidDues = await _context.UserDebts.Where(ud => ud.BuildingId == buildingId && ud.Amount <= 0).CountAsync();
            var unpaidDues = await _context.UserDebts.Where(ud => ud.BuildingId == buildingId && ud.Amount > 0).CountAsync();

            var pendingComplaints = await _context.Complaints.Include(c => c.Unit).Where(c => c.Unit.BuildingId == buildingId && c.Status == "Beklemede").CountAsync();

            var thirtyDaysAgo = DateTime.Now.AddDays(-30);

            return Ok(new
            {
                building.Id,
                building.Name,
                building.Type,
                building.Address,
                UnitCount = building.Units.Count,
                TotalIncome = building.Incomes.Sum(i => i.Amount),
                TotalExpense = building.Expenses.Sum(e => e.Amount),
                Balance = building.Incomes.Sum(i => i.Amount) - building.Expenses.Sum(e => e.Amount),
                UserDebt = currentUserDebt,
                LastPaymentDate = lastPayment?.Date,
                lastSixMonths,
                incomeByMonth,
                expenseByMonth,
                PaidDues = paidDues,
                UnpaidDues = unpaidDues,
                PaidDuesPercentage = totalUnits > 0 ? (int)((paidDues * 100) / totalUnits) : 0,
                PendingComplaints = pendingComplaints,
                RecentIncomeCount = building.Incomes.Count(i => i.Date >= thirtyDaysAgo),
                RecentExpenseCount = building.Expenses.Count(e => e.Date >= thirtyDaysAgo),
                RecentAnnouncements = building.Announcements.Count(a => a.CreatedAt >= thirtyDaysAgo)
            });
        }

        [HttpPost("create")]
        public async Task<IActionResult> Create([FromForm] BuildingViewModel model)
        {
            if (!ModelState.IsValid) return BadRequest(ModelState);

            if (await _buildingService.IsBuildingExistsAsync(model.Name, model.Address))
                return Conflict("Bu isim ve adreste zaten bir bina kayıtlı");

            string imageUrl = null;
            if (model.ImageFile != null && model.ImageFile.Length > 0)
            {
                var uploadsFolder = Path.Combine(_hostingEnvironment.WebRootPath, "BuildsImage");
                if (!Directory.Exists(uploadsFolder)) Directory.CreateDirectory(uploadsFolder);

                var uniqueFileName = Guid.NewGuid().ToString() + Path.GetExtension(model.ImageFile.FileName);
                var filePath = Path.Combine(uploadsFolder, uniqueFileName);

                using var fileStream = new FileStream(filePath, FileMode.Create);
                await model.ImageFile.CopyToAsync(fileStream);
                imageUrl = $"/BuildsImage/{uniqueFileName}";
            }

            var currentUserId = _userManager.GetUserId(User);
            var building = new Building
            {
                Name = model.Name,
                Address = model.Address,
                Type = model.Type,
                Block = model.Block,
                FloorCount = model.FloorCount,
                UnitCount = model.UnitCount,
                Description = model.Description,
                ImageUrl = imageUrl,
                CreatedAt = DateTime.Now
            };

            var (success, message) = await _buildingService.CreateBuildingAsync(building, currentUserId);
            if (success) return Ok(new { message });

            return BadRequest(new { message });
        }

        [HttpPut("{buildingId}")]
        public async Task<IActionResult> Edit(int buildingId, [FromForm] BuildingViewModel model)
        {
            if (buildingId != model.Id) return BadRequest("ID eşleşmiyor");
            if (!ModelState.IsValid) return BadRequest(ModelState);

            var building = await _buildingService.GetBuildingByIdAsync(buildingId);
            if (building == null) return NotFound();

            if (model.ImageFile != null && model.ImageFile.Length > 0)
            {
                var uploadsFolder = Path.Combine(_hostingEnvironment.WebRootPath, "BuildsImage");
                if (!Directory.Exists(uploadsFolder)) Directory.CreateDirectory(uploadsFolder);

                if (!string.IsNullOrEmpty(building.ImageUrl))
                {
                    var oldImagePath = Path.Combine(_hostingEnvironment.WebRootPath, building.ImageUrl.TrimStart('/'));
                    if (System.IO.File.Exists(oldImagePath))
                        System.IO.File.Delete(oldImagePath);
                }

                var uniqueFileName = Guid.NewGuid().ToString() + Path.GetExtension(model.ImageFile.FileName);
                var filePath = Path.Combine(uploadsFolder, uniqueFileName);

                using var fileStream = new FileStream(filePath, FileMode.Create);
                await model.ImageFile.CopyToAsync(fileStream);
                building.ImageUrl = $"/BuildsImage/{uniqueFileName}";
            }

            building.Name = model.Name;
            building.Address = model.Address;
            building.Type = model.Type;
            building.Block = model.Block;
            building.FloorCount = model.FloorCount;
            building.UnitCount = model.UnitCount;
            building.Description = model.Description;

            _context.Update(building);
            await _context.SaveChangesAsync();

            return Ok("Güncelleme başarılı");
        }

        [HttpDelete("{buildingId}")]
        [Authorize(Policy = "BuildingAdmin")]
        public async Task<IActionResult> Delete(int buildingId)
        {
            var building = await _buildingService.GetBuildingByIdAsync(buildingId);
            if (building == null) return NotFound();

            if (!string.IsNullOrEmpty(building.ImageUrl))
            {
                var imagePath = Path.Combine(_hostingEnvironment.WebRootPath, building.ImageUrl.TrimStart('/'));
                if (System.IO.File.Exists(imagePath))
                    System.IO.File.Delete(imagePath);
            }

            _context.Buildings.Remove(building);
            await _context.SaveChangesAsync();

            return Ok("Bina başarıyla silindi");
        }
    }
}
