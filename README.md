# FacuLadder: Career Advancement System for Higher Education Faculties

A comprehensive web-based system for tracking, documenting, and advancing academic careers of faculty members in higher education institutions.

## Features

- **Secure Authentication System**
  - User registration and login
  - Password hashing
  - Password reset via email
  - Role-based access control (Faculty/Admin)

- **Faculty Dashboard**
  - Personal and academic profile management
  - Achievement tracking and documentation
  - Career progression visualization
  - Notification system

- **Admin Panel**
  - Faculty management
  - Document review and approval
  - Career stage updates
  - System administration

- **Career Advancement Tracker**
  - Visual progress indicators
  - Automated eligibility checks
  - Milestone tracking

- **Achievements Management**
  - Upload documents (PDF, images, etc.)
  - Track approvals
  - Filter by type/year

- **Reporting**
  - Downloadable faculty progress reports
  - Achievement summaries

## Transparency Enhancement Features

FacuLadder focuses on increasing transparency in the promotion and career growth process through these specialized features:

- **Public Promotion Criteria Dashboard**
  - Clear visualization of promotion requirements for each academic level
  - Institution-specific criteria management by administrators
  - Real-time updates when requirements change

- **360-Degree Feedback System**
  - Peer review integration for achievements
  - Student feedback collection and analysis
  - Administrative evaluation tracking

- **Achievement Verification Protocol**
  - Blockchain-based document verification
  - Digital signature system for approvals
  - Audit trail for all evaluations

- **Promotion Timeline Forecasting**
  - AI-powered prediction of promotion eligibility dates
  - Gap analysis between current achievements and requirements
  - Personalized action plans for career advancement

- **Interactive Appeals System**
  - Structured process for promotion decision appeals
  - Documentation tracking for appeal cases
  - Resolution timeline monitoring

- **Comparative Analytics**
  - Anonymous peer comparison within departments
  - Institutional benchmarking across similar roles
  - Historical promotion trends visualization

- **Open Documentation Repository**
  - Centralized storage of all institution policies
  - Version control for evolving promotion criteria
  - Searchable knowledge base of past promotion cases

These features collectively create a more transparent, fair, and efficient promotion system for higher education faculty members.

## Technology Stack

- **Backend**: Python Flask
- **Database**: SQLite3
- **Frontend**: HTML, CSS, JavaScript
- **CSS Framework**: Bootstrap 5
- **Icons**: Font Awesome

## Installation

1. Clone the repository:
   ```
   git clone https://github.com/your-username/facultadder.git
   cd facultadder
   ```

2. Create a virtual environment:
   ```
   python -m venv venv
   ```

3. Activate the virtual environment:
   - Windows:
     ```
     venv\Scripts\activate
     ```
   - Unix/MacOS:
     ```
     source venv/bin/activate
     ```

4. Install dependencies:
   ```
   pip install Flask Flask-Login Werkzeug
   ```

5. Run the application:
   ```
   python app.py
   ```

6. Access the application at `http://localhost:5000`

## Default Admin Credentials

- Email: admin@example.com
- Password: admin123

## Project Structure

```
facultadder/
├── app.py                 # Main application file
├── static/                # Static files
│   ├── css/               # CSS stylesheets
│   ├── js/                # JavaScript files
│   └── uploads/           # Uploaded documents
├── templates/             # HTML templates
│   ├── admin/             # Admin panel templates
│   └── faculty/           # Faculty templates
├── faculty_advancement.db # SQLite database
└── README.md              # Project documentation
```

## Usage

1. Register as a faculty member or login using admin credentials
2. Faculty members can:
   - Update their profile
   - Add achievements with supporting documents
   - Track career progress
   - Generate reports

3. Administrators can:
   - View all faculty members
   - Review and approve documents
   - Update faculty career stages
   - Manage the system

## Database Schema

- **users**: User account information and authentication
- **profiles**: Faculty profile data
- **achievements**: Academic and professional achievements
- **admin_reviews**: Document reviews by administrators
- **notifications**: User notifications

## License

[MIT License](LICENSE)

## Acknowledgments

- Built with Flask
- UI designed with Bootstrap
- Icons from Font Awesome

## Email Configuration for Password Reset

To enable the password reset functionality with email delivery:

1. Set up environment variables for email credentials:
   ```
   export EMAIL_USER=your-system-email@gmail.com
   export EMAIL_PASS=your-app-password
   ```

2. If using Gmail:
   - You'll need to generate an "App Password" (not your regular password)
   - Go to your Google Account → Security → 2-Step Verification → App passwords
   - Create a new app password for "Mail" and use it as EMAIL_PASS

3. Alternatively, modify the `send_email` function in `app.py` to use your preferred email service.

---

Developed as an academic project for higher education institutions. 
