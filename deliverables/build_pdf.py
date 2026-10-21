"""Render the 34-page book without requiring desktop Word automation."""
from pathlib import Path
import re
import sys
import tempfile
from xml.sax.saxutils import escape

sys.path.insert(0, str(Path(tempfile.gettempdir())/'mcp-book-libs'))
from reportlab.pdfgen import canvas
from reportlab.lib import colors
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.enums import TA_LEFT, TA_CENTER
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import Paragraph, Table, TableStyle, Image, Spacer, Preformatted

HERE=Path(__file__).resolve().parent
for name,file in [('Arial','arial.ttf'),('Arial-Bold','arialbd.ttf'),('Arial-Italic','ariali.ttf'),
                  ('CalibriLight','calibril.ttf'),('Mono','consola.ttf')]:
    pdfmetrics.registerFont(TTFont(name,str(Path('C:/Windows/Fonts')/file)))
pdfmetrics.registerFontFamily('Arial',normal='Arial',bold='Arial-Bold',italic='Arial-Italic',boldItalic='Arial-Bold')
WIDTH,HEIGHT=595.276,841.89
MARGIN=72
AVAILABLE=WIDTH-2*MARGIN


def style(name='body',size=11,leading=14,**kw):
    return ParagraphStyle(name,fontName='Arial',fontSize=size,leading=leading,spaceAfter=8,**kw)


def para(text,sty):
    text=escape(text)
    text=re.sub(r'(https?://\S+)',r'<link href="\1" color="#1e425e">\1</link>',text)
    return Paragraph(text,sty)


def blocks(page,page_num):
    body=style()
    if page_num==34:body=style(size=9.4,leading=12)
    heading=ParagraphStyle('head',fontName='CalibriLight',fontSize=25,leading=29,spaceAfter=15)
    sub=style('sub',13,16,spaceBefore=6);sub.fontName='Arial-Bold'
    caption=style('caption',9,11);caption.fontName='Arial-Italic'
    flow=[];lines=page.strip().splitlines();i=0
    while i<len(lines):
        line=lines[i].strip()
        if not line:i+=1;continue
        if line.startswith('|'):
            rows=[]
            while i<len(lines) and lines[i].strip().startswith('|'):
                row=[x.strip() for x in lines[i].strip().strip('|').split('|')]
                if not all(re.fullmatch(r'[-: ]+',x) for x in row):rows.append(row)
                i+=1
            # Favor label columns over numeric columns.
            n=len(rows[0]); ratios={2:[.78,.22],3:[.27,.33,.40],4:[.46,.18,.18,.18]}.get(n,[1/n]*n)
            if page_num in [7,8,9,10]:ratios=[.16,.34,.50]
            if page_num in [11,18]:ratios=[.36,.64]
            if page_num in [14,16]:ratios=[.28,.34,.38]
            if page_num==27:ratios=[.28,.15,.17,.40]
            if page_num==31:ratios=[.47,.23,.15,.15]
            data=[]
            for ri,row in enumerate(rows):
                sty=style('cell',9.3,11.7);sty.spaceAfter=0
                if ri==0:sty.fontName='Arial-Bold'
                data.append([para(x,sty) for x in row])
            t=Table(data,colWidths=[AVAILABLE*x for x in ratios],hAlign='LEFT')
            t.setStyle(TableStyle([('BACKGROUND',(0,0),(-1,0),colors.HexColor('#edf0f2')),('GRID',(0,0),(-1,-1),.45,colors.HexColor('#a9afb4')),('VALIGN',(0,0),(-1,-1),'TOP'),('LEFTPADDING',(0,0),(-1,-1),6),('RIGHTPADDING',(0,0),(-1,-1),6),('TOPPADDING',(0,0),(-1,-1),5),('BOTTOMPADDING',(0,0),(-1,-1),5)]))
            flow.extend([t,Spacer(1,10)]);continue
        if line.startswith('```'):
            code=[];i+=1
            while i<len(lines) and not lines[i].startswith('```'):code.append(lines[i]);i+=1
            code_style=style('code',8.4,11.5);code_style.fontName='Mono'
            flow.extend([Preformatted('\n'.join(code),code_style,maxLineLength=91),Spacer(1,8)]);i+=1;continue
        match=re.match(r'!\[(.*?)\]\((.*?)\)',line)
        if match:
            im=Image(str(HERE/match.group(2)));im.drawHeight=im.imageHeight*AVAILABLE/im.imageWidth;im.drawWidth=AVAILABLE
            flow.extend([im,Spacer(1,6)]);i+=1;continue
        if line.startswith('# '):flow.append(para(line[2:],heading))
        elif line.startswith('## '):flow.append(para(line[3:],sub))
        else:flow.append(para(line,caption if line.startswith('Figure ') else body))
        i+=1
    return flow


def main():
    pages=(HERE/'MCP_Project_Book.md').read_text(encoding='utf-8').split('<!-- PAGE -->')
    c=canvas.Canvas(str(HERE/'MCP_Project_Book.pdf'),pagesize=(WIDTH,HEIGHT))
    c.setTitle('Static Security Analysis of Model Context Protocol Servers')
    c.setAuthor('Bar David and Noam Ben Lulu')
    c.setSubject('Technion B.Sc. final project; 11 October 2026 validation snapshot')
    heights=[]
    for page_num,page in enumerate(pages,1):
        c.setFont('Arial',10);c.drawCentredString(WIDTH/2,35,str(page_num))
        if page_num==1:
            y=HEIGHT-118
            for line in page.strip().splitlines():
                line=line.strip()
                if not line:continue
                if line.startswith('# '):
                    p=para(line[2:],ParagraphStyle('cover',fontName='CalibriLight',fontSize=27,leading=34,alignment=TA_CENTER))
                    w,h=p.wrap(AVAILABLE,700);p.drawOn(c,MARGIN,y-h);y-=h+24;continue
                if line in ['Submitted by','Supervisor']:y-=17
                if re.search(r'[\u0590-\u05ff]',line):line=line[::-1]
                c.setFont('Arial-Bold' if line in ['Submitted by','Supervisor'] else 'Arial',10 if line.startswith(('Submission date','Implementation')) else 12)
                c.drawCentredString(WIDTH/2,y,line);y-=26
            heights.append({'page':1,'remaining':round(y-62,1)})
        else:
            items=blocks(page,page_num);measures=[]
            for item in items:
                w,h=item.wrap(AVAILABLE,1000);before=item.getSpaceBefore();after=item.getSpaceAfter()
                measures.append((item,h,before,after))
            total=sum(h+b+a for _,h,b,a in measures)
            if total>HEIGHT-65-62:raise RuntimeError(f'Page {page_num} overflows: {total:.1f}pt')
            y=HEIGHT-65
            title=next(x[2:] for x in page.strip().splitlines() if x.startswith('# '))
            c.bookmarkPage(f'page-{page_num}');c.addOutlineEntry(title,f'page-{page_num}',0)
            for item,h,before,after in measures:
                y-=before+h;item.drawOn(c,MARGIN,y);y-=after
            heights.append({'page':page_num,'used_points':round(total,1),'remaining':round(y-62,1)})
        c.showPage()
    c.save()
    import json
    (HERE/'working/pdf_layout_check.json').write_text(json.dumps(heights,indent=2))
    print('Saved 34-page PDF; tightest bottom clearance',min(x['remaining'] for x in heights))


if __name__=='__main__':main()
