// pdfRoutes.js
const express = require("express");
const router = express.Router();
const fs = require("fs");
const path = require("path");
const Handlebars = require("handlebars");
const puppeteer = require("puppeteer");

// We'll assume you have an endpoint: POST /api/generatePdf
// The front end can send the user's data (maintenanceCals, macros, etc.) 
router.post("/generatePdf", async (req, res) => {
  try {
    // 1) Extract data from the request body
    //    We'll expect { userName, maintenanceCalories, macros, etc. }
    const {
      username,        // from your getUserProfile or user context
      maintenanceCals, // from your BMR calculation
      proteinGrams,
      carbGrams,
      fatGrams
    } = req.body;

    // 2) Also compute bulkCals = maintenanceCals + 500
    //    and cutCals = maintenanceCals - 500
    const bulkCalories = maintenanceCals + 500;
    const cutCalories = maintenanceCals - 500;

    // 3) Load the HTML template
    const templatePath = path.join(__dirname, "..", "templates", "NutritionTemplate.html");
    const templateStr = fs.readFileSync(templatePath, "utf-8");

    // 4) Use Handlebars to compile
    const template = Handlebars.compile(templateStr);

    // 5) Render final HTML by passing in the data
    const htmlContent = template({
      username,
      maintenanceCalories: maintenanceCals,
      bulkCalories,
      cutCalories,
      proteinGrams,
      carbGrams,
      fatGrams
    });

    // 6) Launch Puppeteer
    const browser = await puppeteer.launch();
    const page = await browser.newPage();
    // Provide our rendered HTML
    await page.setContent(htmlContent, { waitUntil: "networkidle0" });

    // 7) Generate PDF
    const pdfBuffer = await page.pdf({
      format: "A4",
      printBackground: true
    });

    await browser.close();

    // 8) Send the PDF back to the browser
    res.setHeader("Content-Type", "application/pdf");
    res.setHeader("Content-Disposition", 'attachment; filename="Nutrition101.pdf"');
    return res.send(pdfBuffer);

  } catch (err) {
    console.error("Error generating PDF:", err);
    return res.status(500).send("Failed to generate PDF.");
  }
});

module.exports = router;
