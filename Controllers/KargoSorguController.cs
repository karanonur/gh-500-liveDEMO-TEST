using Microsoft.AspNetCore.Mvc;
using System.Data.SqlClient;

namespace _1202demoapp.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class KargoSorguController : ControllerBase
    {
        private readonly string connectionString = "Server=localhost;Database=SuratKargoDB;Trusted_Connection=True;";

        [HttpGet("takip/{takipNo}")]
        public IActionResult GetKargoDurumu(string takipNo)
        {
            // ❌ ZAAFİYET 1: SQL Injection (Kullanıcı girdisi doğrudan sorgu dizisine eklenmiş)
            string query = "SELECT * FROM KargoGonderileri WHERE TakipNo = '" + takipNo + "'";

            SqlConnection conn = new SqlConnection(connectionString);
            SqlCommand cmd = new SqlCommand(query, conn);
            conn.Open();

            // ❌ KOD HATASI 1: Unhandled Resource Leak (using bloğu kullanılmamış, bağlantı/reader açık kalıyor)
            SqlDataReader reader = cmd.ExecuteReader(); 

            if (reader.Read())
            {
                string aliciAdi = reader["AliciAdi"].ToString();
                return Ok(new { TakipNo = takipNo, Alici = aliciAdi });
            }

            return NotFound("Kargo bulunamadı.");
        }
    }
}
