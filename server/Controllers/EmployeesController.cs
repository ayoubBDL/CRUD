using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using server.Models;

namespace server.Controllers
{
    [ApiController]
    [Route("api/employees")]
    public class EmployeesController : Controller
    {
        private readonly ServerDbContext _serverDbContext;
        public EmployeesController(ServerDbContext serverDbContext)
        {
            _serverDbContext = serverDbContext;
        }

        [HttpGet]
        public async Task<IActionResult> GetAllEmployees()
        {
            var employees = await _serverDbContext.Employees.ToListAsync();
            
            return Ok(employees);
        }
        [HttpPost]
        public async Task<IActionResult> AddEmployee([FromBody] Employee employeeRequest)
        {
            employeeRequest.Id = Guid.NewGuid();
            await _serverDbContext.Employees.AddAsync(employeeRequest);
            await _serverDbContext.SaveChangesAsync();
            
            return Ok(employeeRequest);
        }

        [HttpGet]
        [Route("{id:Guid}")]
        public async Task<IActionResult> GetEmployee([FromRoute] Guid id)
        {
            var employee = await _serverDbContext.Employees.FirstOrDefaultAsync(x => x.Id == id);
            
            if(employee == null){
                return NotFound();
            }
            
            return Ok(employee);
        }

        [HttpPut]
        [Route("{id:Guid}")]
        public async Task<IActionResult> UpdateEmployee([FromRoute] Guid id, Employee updatedEmployee)
        {
            
            var employee = await _serverDbContext.Employees.FindAsync(id);
            if(employee == null){
                return NotFound();
            }
            employee.Name = updatedEmployee.Name;
            employee.Salary = updatedEmployee.Salary;
            employee.Department = updatedEmployee.Department;
            employee.Email = updatedEmployee.Email;
            employee.Phone = updatedEmployee.Phone;
            await _serverDbContext.SaveChangesAsync();
            
            
            return Ok(employee);
        }

        [HttpDelete]
        [Route("{id:Guid}")]
        public async Task<IActionResult> DeleteEmployee([FromRoute] Guid id)
        {
            
            var employee = await _serverDbContext.Employees.FindAsync(id);
            if(employee == null){
                return NotFound();
            }
            
            _serverDbContext.Remove(employee);
            await _serverDbContext.SaveChangesAsync();
            
            
            return Ok(employee);
        }

    }
}